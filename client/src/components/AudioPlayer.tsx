import { useState, useRef, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Slider } from '@/components/ui/slider';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Sheet, SheetContent, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import {
  Play, Pause, SkipBack, SkipForward, Volume2, VolumeX,
  Shuffle, Repeat, Repeat1, List, ChevronUp, Heart,
  MoreHorizontal, X, Clock, Disc3
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useMutation, useQuery } from '@tanstack/react-query';
import { apiRequest, queryClient } from '@/lib/queryClient';
import type { File } from '@shared/schema';

interface AudioTrack extends File {
  artistName?: string;
  albumName?: string;
}

interface AudioPlayerProps {
  className?: string;
}

export function AudioPlayer({ className }: AudioPlayerProps) {
  const audioRef = useRef<HTMLAudioElement>(null);
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(0);
  const [volume, setVolume] = useState(1);
  const [isMuted, setIsMuted] = useState(false);
  const [isShuffling, setIsShuffling] = useState(false);
  const [repeatMode, setRepeatMode] = useState<'none' | 'all' | 'one'>('none');
  const [showQueue, setShowQueue] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);
  const [currentTrack, setCurrentTrack] = useState<AudioTrack | null>(null);
  const [queue, setQueue] = useState<AudioTrack[]>([]);
  const [queueIndex, setQueueIndex] = useState(0);
  const [playlistId, setPlaylistId] = useState<string | null>(null);
  const [accessTokens, setAccessTokens] = useState<Map<string, string>>(new Map());
  const playStartTime = useRef<number>(0);

  // Record play history
  const recordPlayMutation = useMutation({
    mutationFn: (data: { fileId: string; playlistId?: string; duration: number; completed: boolean }) => 
      apiRequest('/api/play-history', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/recently-played'] });
    },
  });
  
  // Generate access token for audio files
  const generateAccessToken = async (fileId: string): Promise<string> => {
    if (accessTokens.has(fileId)) {
      return accessTokens.get(fileId)!;
    }
    
    try {
      const response = await apiRequest(`/api/media/${fileId}/access-token`, {
        method: 'POST',
      });
      const data = await response.json();
      const token = data.token;
      
      setAccessTokens(prev => new Map(prev).set(fileId, token));
      
      // Clear token after 9 minutes (tokens expire at 10 minutes)
      setTimeout(() => {
        setAccessTokens(prev => {
          const newMap = new Map(prev);
          newMap.delete(fileId);
          return newMap;
        });
      }, 9 * 60 * 1000);
      
      return token;
    } catch (error) {
      console.error('Failed to generate access token:', error);
      throw error;
    }
  };

  // Handle audio element events
  useEffect(() => {
    const audio = audioRef.current;
    if (!audio) return;

    const handleTimeUpdate = () => {
      setCurrentTime(audio.currentTime);
    };

    const handleLoadedMetadata = () => {
      setDuration(audio.duration);
    };

    const handleEnded = () => {
      if (currentTrack && currentTrack.id) {
        const playDuration = Date.now() - playStartTime.current;
        recordPlayMutation.mutate({
          fileId: currentTrack.id,
          playlistId: playlistId || undefined,
          duration: Math.floor(playDuration / 1000),
          completed: true,
        });
      }
      
      if (repeatMode === 'one') {
        audio.currentTime = 0;
        audio.play();
      } else {
        handleNext();
      }
    };

    audio.addEventListener('timeupdate', handleTimeUpdate);
    audio.addEventListener('loadedmetadata', handleLoadedMetadata);
    audio.addEventListener('ended', handleEnded);

    return () => {
      audio.removeEventListener('timeupdate', handleTimeUpdate);
      audio.removeEventListener('loadedmetadata', handleLoadedMetadata);
      audio.removeEventListener('ended', handleEnded);
    };
  }, [currentTrack, repeatMode, playlistId]);

  // Play/pause toggle
  const togglePlayPause = () => {
    const audio = audioRef.current;
    if (!audio || !currentTrack) return;

    if (isPlaying) {
      audio.pause();
      setIsPlaying(false);
      
      // Record partial play (skip if mutation is pending to avoid connection pool issues)
      const playDuration = Date.now() - playStartTime.current;
      if (playDuration > 3000 && currentTrack.id && !recordPlayMutation.isPending) {
        recordPlayMutation.mutate({
          fileId: currentTrack.id,
          playlistId: playlistId || undefined,
          duration: Math.floor(playDuration / 1000),
          completed: false,
        });
      }
    } else {
      audio.play().then(() => {
        setIsPlaying(true);
        playStartTime.current = Date.now();
      }).catch(err => {
        if (err.name !== 'AbortError') {
          console.error('Failed to play audio:', err);
        }
        setIsPlaying(false);
      });
    }
  };

  // Skip to previous track
  const handlePrevious = () => {
    const audio = audioRef.current;
    if (!audio) return;

    // If more than 3 seconds into the song, restart it
    if (currentTime > 3) {
      audio.currentTime = 0;
      return;
    }

    if (queue.length === 0) return;

    let newIndex = queueIndex - 1;
    if (newIndex < 0) {
      newIndex = repeatMode === 'all' ? queue.length - 1 : 0;
    }

    playTrack(queue[newIndex], newIndex);
  };

  // Skip to next track
  const handleNext = () => {
    if (queue.length === 0) return;

    let newIndex = queueIndex + 1;
    if (newIndex >= queue.length) {
      if (repeatMode === 'all') {
        newIndex = 0;
      } else {
        setIsPlaying(false);
        return;
      }
    }

    if (isShuffling && repeatMode !== 'one') {
      newIndex = Math.floor(Math.random() * queue.length);
    }

    playTrack(queue[newIndex], newIndex);
  };

  // Play a specific track
  const playTrack = async (track: AudioTrack, index: number) => {
    setCurrentTrack(track);
    setQueueIndex(index);
    
    const audio = audioRef.current;
    if (audio) {
      // Stop current track properly
      if (isPlaying) {
        audio.pause();
        setIsPlaying(false);
      }
      
      // Load new track with access token
      try {
        const token = await generateAccessToken(track.id);
        audio.src = `/api/media/${track.id}?token=${token}`;
      } catch (error) {
        console.error('Failed to load track with access token:', error);
        // Fallback to direct URL (might fail but worth trying)
        audio.src = `/api/media/${track.id}`;
      }
      
      audio.load();
      
      // Wait for audio to be ready before playing
      const handleCanPlay = () => {
        audio.play().then(() => {
          setIsPlaying(true);
          playStartTime.current = Date.now();
        }).catch(err => {
          // Only log error if it's not an abort error
          if (err.name !== 'AbortError') {
            console.error('Failed to play audio:', err);
          }
          setIsPlaying(false);
        });
        
        // Remove the event listener after playing
        audio.removeEventListener('canplay', handleCanPlay);
      };
      
      // Add event listener for when audio is ready
      audio.addEventListener('canplay', handleCanPlay);
      
      // Cleanup in case track changes before canplay
      setTimeout(() => {
        audio.removeEventListener('canplay', handleCanPlay);
      }, 30000); // Remove after 30 seconds to prevent memory leaks
    }
  };

  // Add track to queue
  const addToQueue = (track: AudioTrack) => {
    setQueue([...queue, track]);
    if (!currentTrack) {
      playTrack(track, 0);
    }
  };

  // Play entire playlist
  const playPlaylist = (tracks: AudioTrack[], startIndex: number = 0, playlistId?: string) => {
    if (tracks.length === 0) return;
    
    setQueue(tracks);
    setPlaylistId(playlistId || null);
    playTrack(tracks[startIndex], startIndex);
  };

  // Remove from queue
  const removeFromQueue = (index: number) => {
    const newQueue = queue.filter((_, i) => i !== index);
    setQueue(newQueue);
    
    if (index < queueIndex) {
      setQueueIndex(queueIndex - 1);
    } else if (index === queueIndex && newQueue.length > 0) {
      const newIndex = Math.min(queueIndex, newQueue.length - 1);
      playTrack(newQueue[newIndex], newIndex);
    } else if (newQueue.length === 0) {
      setCurrentTrack(null);
      setIsPlaying(false);
      setQueueIndex(0);
    }
  };

  // Clear queue
  const clearQueue = () => {
    setQueue([]);
    setCurrentTrack(null);
    setIsPlaying(false);
    setQueueIndex(0);
    
    const audio = audioRef.current;
    if (audio) {
      audio.pause();
      audio.src = '';
    }
  };

  // Handle volume change
  const handleVolumeChange = (value: number[]) => {
    const newVolume = value[0];
    setVolume(newVolume);
    setIsMuted(newVolume === 0);
    
    const audio = audioRef.current;
    if (audio) {
      audio.volume = newVolume;
    }
  };

  // Toggle mute
  const toggleMute = () => {
    const audio = audioRef.current;
    if (!audio) return;

    if (isMuted) {
      audio.volume = volume || 0.5;
      setVolume(volume || 0.5);
      setIsMuted(false);
    } else {
      audio.volume = 0;
      setIsMuted(true);
    }
  };

  // Toggle repeat mode
  const toggleRepeatMode = () => {
    const modes: Array<'none' | 'all' | 'one'> = ['none', 'all', 'one'];
    const currentIndex = modes.indexOf(repeatMode);
    const nextIndex = (currentIndex + 1) % modes.length;
    setRepeatMode(modes[nextIndex]);
  };

  // Handle seeking
  const handleSeek = (value: number[]) => {
    const audio = audioRef.current;
    if (!audio || !currentTrack) return;
    
    const newTime = value[0];
    audio.currentTime = newTime;
    setCurrentTime(newTime);
    
    // Reset play start time when seeking (don't record play history on seek to avoid DB issues)
    if (isPlaying) {
      playStartTime.current = Date.now();
    }
  };

  // Format time for display
  const formatTime = (seconds: number) => {
    if (!seconds || isNaN(seconds)) return '0:00';
    
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  // Expose methods for external use
  useEffect(() => {
    // Store player methods globally for other components to use
    (window as any).audioPlayer = {
      playTrack,
      addToQueue,
      playPlaylist,
      clearQueue,
      getCurrentTrack: () => currentTrack,
      getQueue: () => queue,
      isPlaying: () => isPlaying,
    };
  }, [currentTrack, queue, isPlaying]);

  if (!currentTrack) {
    return null;
  }

  return (
    <>
      <audio ref={audioRef} />
      
      {/* Main Player Bar */}
      <div className={cn(
        "fixed bottom-0 left-0 right-0 bg-black border-t border-neutral-800 p-4 z-50",
        className
      )}
      data-testid="audio-player">
        <div className="max-w-screen-2xl mx-auto flex items-center justify-between gap-4">
          {/* Track Info */}
          <div className="flex items-center gap-3 min-w-[180px] w-[30%]">
            {currentTrack.thumbnailData ? (
              <img 
                src={`data:image/jpeg;base64,${btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(currentTrack.thumbnailData))))}`}
                alt={currentTrack.originalName}
                className="w-14 h-14 rounded object-cover"
              />
            ) : (
              <div className="w-14 h-14 bg-neutral-800 rounded flex items-center justify-center">
                <Disc3 className="w-6 h-6 text-neutral-600" />
              </div>
            )}
            
            <div className="flex-1 min-w-0">
              <div className="text-white font-medium truncate" data-testid="track-title">
                {currentTrack.originalName}
              </div>
              <div className="text-neutral-400 text-sm truncate" data-testid="track-artist">
                {currentTrack.artistName || 'Unknown Artist'}
              </div>
            </div>
            
            <Button
              variant="ghost"
              size="icon"
              className="text-neutral-400 hover:text-white"
              data-testid="button-favorite"
            >
              <Heart className="w-5 h-5" />
            </Button>
          </div>

          {/* Playback Controls */}
          <div className="flex flex-col items-center gap-2 flex-1 max-w-[722px]">
            <div className="flex items-center gap-4">
              <Button
                variant="ghost"
                size="icon"
                onClick={() => setIsShuffling(!isShuffling)}
                className={cn(
                  "text-neutral-400 hover:text-white",
                  isShuffling && "text-green-500"
                )}
                data-testid="button-shuffle"
              >
                <Shuffle className="w-4 h-4" />
              </Button>
              
              <Button
                variant="ghost"
                size="icon"
                onClick={handlePrevious}
                className="text-neutral-400 hover:text-white"
                data-testid="button-previous"
              >
                <SkipBack className="w-5 h-5 fill-current" />
              </Button>
              
              <Button
                variant="ghost"
                size="icon"
                onClick={togglePlayPause}
                className="bg-white text-black hover:bg-white/90 rounded-full w-8 h-8"
                data-testid="button-play-pause"
              >
                {isPlaying ? (
                  <Pause className="w-4 h-4 fill-current" />
                ) : (
                  <Play className="w-4 h-4 fill-current ml-0.5" />
                )}
              </Button>
              
              <Button
                variant="ghost"
                size="icon"
                onClick={handleNext}
                className="text-neutral-400 hover:text-white"
                data-testid="button-next"
              >
                <SkipForward className="w-5 h-5 fill-current" />
              </Button>
              
              <Button
                variant="ghost"
                size="icon"
                onClick={toggleRepeatMode}
                className={cn(
                  "text-neutral-400 hover:text-white",
                  repeatMode !== 'none' && "text-green-500"
                )}
                data-testid="button-repeat"
              >
                {repeatMode === 'one' ? (
                  <Repeat1 className="w-4 h-4" />
                ) : (
                  <Repeat className="w-4 h-4" />
                )}
              </Button>
            </div>
            
            {/* Progress Bar */}
            <div className="flex items-center gap-2 w-full">
              <span className="text-xs text-neutral-400 w-10 text-right">
                {formatTime(currentTime)}
              </span>
              
              <Slider
                value={[currentTime]}
                max={duration || 100}
                step={1}
                onValueChange={handleSeek}
                className="flex-1"
                data-testid="slider-progress"
              />
              
              <span className="text-xs text-neutral-400 w-10">
                {formatTime(duration)}
              </span>
            </div>
          </div>

          {/* Right Controls */}
          <div className="flex items-center gap-2 min-w-[180px] w-[30%] justify-end">
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setShowQueue(true)}
              className="text-neutral-400 hover:text-white"
              data-testid="button-queue"
            >
              <List className="w-5 h-5" />
            </Button>
            
            <Button
              variant="ghost"
              size="icon"
              onClick={toggleMute}
              className="text-neutral-400 hover:text-white"
              data-testid="button-volume"
            >
              {isMuted || volume === 0 ? (
                <VolumeX className="w-5 h-5" />
              ) : (
                <Volume2 className="w-5 h-5" />
              )}
            </Button>
            
            <Slider
              value={[isMuted ? 0 : volume]}
              max={1}
              step={0.01}
              onValueChange={handleVolumeChange}
              className="w-24"
              data-testid="slider-volume"
            />
            
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setIsExpanded(!isExpanded)}
              className="text-neutral-400 hover:text-white"
              data-testid="button-expand"
            >
              <ChevronUp className={cn(
                "w-5 h-5 transition-transform",
                isExpanded && "rotate-180"
              )} />
            </Button>
          </div>
        </div>
      </div>

      {/* Queue Sheet */}
      <Sheet open={showQueue} onOpenChange={setShowQueue}>
        <SheetContent side="right" className="w-[400px] bg-neutral-900 border-neutral-800">
          <SheetHeader>
            <SheetTitle className="text-white">Queue</SheetTitle>
          </SheetHeader>
          
          <div className="mt-4">
            {queue.length === 0 ? (
              <div className="text-center text-neutral-400 py-8">
                <Clock className="w-12 h-12 mx-auto mb-2 opacity-50" />
                <p>Queue is empty</p>
              </div>
            ) : (
              <ScrollArea className="h-[calc(100vh-120px)]">
                <div className="space-y-2">
                  {queue.map((track, index) => (
                    <div
                      key={`${track.id}-${index}`}
                      className={cn(
                        "flex items-center gap-3 p-2 rounded hover:bg-white/5",
                        index === queueIndex && "bg-white/10"
                      )}
                      data-testid={`queue-item-${index}`}
                    >
                      <div className="flex-1 min-w-0">
                        <div className="text-white text-sm truncate">
                          {track.originalName}
                        </div>
                        <div className="text-neutral-400 text-xs truncate">
                          {track.artistName || 'Unknown Artist'}
                        </div>
                      </div>
                      
                      {index === queueIndex && isPlaying && (
                        <div className="text-green-500 text-xs">
                          Playing
                        </div>
                      )}
                      
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => removeFromQueue(index)}
                        className="text-neutral-400 hover:text-white h-8 w-8"
                        data-testid={`button-remove-${index}`}
                      >
                        <X className="w-4 h-4" />
                      </Button>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            )}
            
            {queue.length > 0 && (
              <div className="mt-4 pt-4 border-t border-neutral-800">
                <Button
                  variant="outline"
                  onClick={clearQueue}
                  className="w-full"
                  data-testid="button-clear-queue"
                >
                  Clear Queue
                </Button>
              </div>
            )}
          </div>
        </SheetContent>
      </Sheet>
    </>
  );
}