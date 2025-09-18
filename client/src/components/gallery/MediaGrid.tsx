import { useState, useRef, useEffect } from "react";
import { Play, Lock, Heart, Download, Eye, EyeOff, Check, Square, CheckSquare } from "lucide-react";
import type { MediaFile } from "@shared/schema";

interface MediaGridProps {
  mediaFiles: MediaFile[];
  isLoading: boolean;
  selectedIndex: number;
  focusedIndex?: number;
  onMediaSelect: (mediaId: string, index: number) => void;
  isVaultMode?: boolean;
  decryptionKey?: string | null;
  // Selection props
  selectedItems?: Set<string>;
  onItemSelect?: (itemId: string, selected: boolean) => void;
  onSelectAll?: () => void;
  // Infinite scroll props
  isFetchingMore?: boolean;
  sentinelRef?: React.RefObject<HTMLDivElement>;
}

export default function MediaGrid({ 
  mediaFiles, 
  isLoading, 
  selectedIndex, 
  focusedIndex = 0,
  onMediaSelect, 
  isVaultMode = false,
  decryptionKey,
  selectedItems = new Set<string>(),
  onItemSelect,
  onSelectAll,
  isFetchingMore = false,
  sentinelRef
}: MediaGridProps) {
  const gridRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Scroll focused item into view
    if (focusedIndex >= 0 && gridRef.current) {
      const focusedItem = gridRef.current.children[focusedIndex] as HTMLElement;
      if (focusedItem) {
        focusedItem.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }
  }, [focusedIndex]);

  if (isLoading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-4" data-testid="media-grid-loading">
        {Array.from({ length: 20 }).map((_, i) => (
          <div key={i} className="aspect-square bg-card rounded-lg border border-border animate-pulse" />
        ))}
      </div>
    );
  }

  if (mediaFiles.length === 0) {
    return (
      <div className="text-center py-12" data-testid="media-grid-empty">
        <div className="w-16 h-16 bg-muted rounded-full flex items-center justify-center mx-auto mb-4">
          <Eye className="w-8 h-8 text-muted-foreground" />
        </div>
        <h3 className="text-lg font-semibold mb-2">No Media Found</h3>
        <p className="text-muted-foreground">
          {isVaultMode ? "No encrypted content in your vault" : "Upload some photos and videos to get started"}
        </p>
      </div>
    );
  }

  return (
    <>
      <div 
        ref={gridRef}
        className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-4" 
        data-testid="media-grid"
      >
        {mediaFiles.map((file, index) => (
          <MediaGridItem
            key={file.id}
            file={file}
            index={index}
            isSelected={index === selectedIndex}
            isFocused={index === focusedIndex}
            isVaultMode={isVaultMode}
            decryptionKey={decryptionKey}
            onClick={() => onMediaSelect(file.id, index)}
            isChecked={selectedItems.has(file.id)}
            onCheckboxClick={(e) => {
              e.stopPropagation();
              onItemSelect?.(file.id, !selectedItems.has(file.id));
            }}
          />
        ))}
      </div>
      
      {/* Sentinel element for infinite scroll */}
      {sentinelRef && (
        <div ref={sentinelRef} className="h-1" data-testid="infinite-scroll-sentinel" />
      )}
      
      {/* Loading indicator for more items */}
      {isFetchingMore && (
        <div className="flex justify-center py-8" data-testid="loading-more">
          <div className="flex items-center gap-3">
            <div className="animate-spin w-5 h-5 border-2 border-primary border-t-transparent rounded-full"></div>
            <span className="text-muted-foreground">Loading more items...</span>
          </div>
        </div>
      )}
    </>
  );
}

interface MediaGridItemProps {
  file: MediaFile;
  index: number;
  isSelected: boolean;
  isFocused: boolean;
  isVaultMode: boolean;
  decryptionKey?: string | null;
  onClick: () => void;
  isChecked: boolean;
  onCheckboxClick: (e: React.MouseEvent) => void;
}

function MediaGridItem({ file, index, isSelected, isFocused, isVaultMode, decryptionKey, onClick, isChecked, onCheckboxClick }: MediaGridItemProps) {
  const [imageLoaded, setImageLoaded] = useState(false);
  const [imageError, setImageError] = useState(false);
  const [thumbnailBlobUrl, setThumbnailBlobUrl] = useState<string | null>(null);
  const [isHovered, setIsHovered] = useState(false);
  const [showVideo, setShowVideo] = useState(false);

  const isVideo = file.mimeType.startsWith('video/');
  const isEncrypted = file.isEncrypted;
  
  // Get video URL for autoplay
  const getVideoUrl = () => {
    if (isVideo && !isEncrypted) {
      return `/api/media/${file.id}`;
    } else if (isVideo && isEncrypted && isVaultMode && decryptionKey) {
      // Pass vault token as URL parameter for video elements
      return `/api/media/${file.id}?decrypt=true&vt=${encodeURIComponent(decryptionKey)}`;
    }
    return null;
  };
  
  const videoUrl = getVideoUrl();
  
  // Determine thumbnail URL (secure - no keys in URL)
  const getThumbnailUrl = () => {
    if (isEncrypted && isVaultMode && decryptionKey) {
      // For encrypted content, use decrypt parameter but NO key in URL
      return `/api/media/${file.id}/thumbnail?decrypt=true`;
    } else if (!isEncrypted) {
      return `/api/media/${file.id}/thumbnail`;
    }
    return null; // Will show placeholder for encrypted content without key
  };

  const thumbnailUrl = getThumbnailUrl();

  // Fetch encrypted thumbnails securely using Authorization headers
  useEffect(() => {
    if (isEncrypted && isVaultMode && decryptionKey && thumbnailUrl) {
      const fetchSecureThumbnail = async () => {
        try {
          const response = await fetch(thumbnailUrl, {
            method: 'GET',
            headers: {
              'X-Vault-Token': decryptionKey,
            },
            credentials: 'include',
          });

          if (response.ok) {
            const blob = await response.blob();
            const blobUrl = URL.createObjectURL(blob);
            setThumbnailBlobUrl(blobUrl);
            setImageLoaded(true);
          } else {
            console.error('Failed to fetch encrypted thumbnail:', response.status);
            setImageError(true);
          }
        } catch (error) {
          console.error('Error fetching encrypted thumbnail:', error);
          setImageError(true);
        }
      };

      fetchSecureThumbnail();

      // Cleanup blob URL on unmount
      return () => {
        if (thumbnailBlobUrl) {
          URL.revokeObjectURL(thumbnailBlobUrl);
        }
      };
    }
  }, [file.id, isEncrypted, isVaultMode, decryptionKey, thumbnailUrl]);

  // Use blob URL for encrypted content, regular URL for non-encrypted
  const displayUrl = isEncrypted && isVaultMode && decryptionKey ? thumbnailBlobUrl : thumbnailUrl;

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  const formatDuration = (seconds: number): string => {
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
  };

  return (
    <div
      className={`
        bg-card rounded-lg border overflow-hidden transition-all duration-300 cursor-pointer group relative
        hover:transform hover:translate-y-[-4px] hover:scale-[1.02] hover:shadow-lg hover:shadow-primary/20
        ${isFocused ? 'ring-2 ring-blue-500 ring-offset-2 ring-offset-background shadow-lg' : 'border-border'}
        ${isSelected ? 'keyboard-nav-active ring-2 ring-accent ring-offset-2 ring-offset-background' : ''}
        ${isEncrypted && isVaultMode ? 'border-accent/50 shadow-sm shadow-accent/10' : ''}
        ${isChecked ? 'ring-2 ring-primary ring-offset-2 ring-offset-background' : ''}
      `}
      onClick={onClick}
      onMouseEnter={() => {
        setIsHovered(true);
        if (isVideo && videoUrl) {
          setShowVideo(true);
        }
      }}
      onMouseLeave={() => {
        setIsHovered(false);
        setShowVideo(false);
      }}
      onFocus={() => {
        if (isVideo && videoUrl) {
          setShowVideo(true);
        }
      }}
      onBlur={() => {
        setShowVideo(false);
      }}
      tabIndex={0}
      data-media-type={isVideo ? 'video' : 'image'}
      data-index={index}
      data-testid={`media-item-${index}`}
    >
      <div className="aspect-square relative">
        {/* Video autoplay on hover/focus */}
        {isVideo && showVideo && videoUrl && (isHovered || isSelected) ? (
          <video
            src={videoUrl}
            className="w-full h-full object-cover"
            autoPlay
            muted
            loop
            playsInline
            onLoadStart={() => setImageLoaded(true)}
            data-testid="video-autoplay"
          />
        ) : displayUrl ? (
          <>
            <img
              src={displayUrl}
              alt={file.originalName}
              className={`w-full h-full object-cover transition-opacity duration-300 ${
                imageLoaded ? 'opacity-100' : 'opacity-0'
              } ${imageError ? 'hidden' : ''}`}
              onLoad={() => !isEncrypted && setImageLoaded(true)} // For encrypted, loading is handled in useEffect
              onError={() => setImageError(true)}
            />
            
            {/* Loading placeholder */}
            {!imageLoaded && !imageError && (
              <div className="w-full h-full bg-gradient-to-br from-primary/10 to-accent/10 flex items-center justify-center">
                <div className="animate-spin w-6 h-6 border-2 border-primary border-t-transparent rounded-full"></div>
              </div>
            )}
          </>
        ) : (
          /* Encrypted content placeholder */
          <div className="w-full h-full bg-gradient-to-br from-accent/20 to-accent/5 flex items-center justify-center">
            <div className="text-center">
              <Lock className="w-8 h-8 text-accent mx-auto mb-2" />
              <div className="text-accent text-xs font-semibold">ENCRYPTED</div>
            </div>
          </div>
        )}

        {/* Error state */}
        {imageError && (
          <div className="w-full h-full bg-muted flex items-center justify-center">
            <div className="text-center">
              <EyeOff className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
              <div className="text-xs text-muted-foreground">Failed to load</div>
            </div>
          </div>
        )}

        {/* Video Play Indicator */}
        {isVideo && (
          <>
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="w-12 h-12 bg-white/90 rounded-full flex items-center justify-center shadow-lg transition-opacity hover:opacity-75">
                <Play className="w-5 h-5 text-gray-800 ml-0.5" />
              </div>
            </div>
            {/* Duration Badge - moved to bottom-left */}
            {file.duration && (
              <div className="absolute bottom-3 left-3 px-2 py-1 bg-black/80 rounded text-white text-xs font-medium">
                {formatDuration(file.duration)}
              </div>
            )}
          </>
        )}

        {/* Vault/Encrypted Badge - moved to bottom-left */}
        {isEncrypted && (
          <div className="absolute bottom-3 left-3 px-2 py-1 bg-accent/90 rounded text-white text-xs font-medium flex items-center gap-1">
            <Lock className="w-3 h-3" />
            {isVaultMode && decryptionKey ? 'DECRYPTED' : 'ENCRYPTED'}
          </div>
        )}

        {/* Favorite Badge */}
        {file.isFavorite && (
          <div className="absolute bottom-3 right-3 p-1 bg-black/50 rounded z-10">
            <Heart className="w-4 h-4 text-red-400 fill-current" />
          </div>
        )}

        {/* Selection Checkbox - moved to top-right corner */}
        <div className="absolute top-3 right-3 z-10">
          <button
            className={`
              w-6 h-6 rounded flex items-center justify-center transition-all
              ${isChecked 
                ? 'bg-primary text-white scale-110 shadow-lg' 
                : 'bg-white/80 border-2 border-gray-500 hover:bg-white hover:scale-110 hover:shadow-md opacity-0 group-hover:opacity-100'
              }
            `}
            onClick={onCheckboxClick}
            data-testid={`checkbox-item-${index}`}
          >
            {isChecked ? (
              <Check className="w-4 h-4" />
            ) : (
              <Square className="w-3 h-3 text-gray-600" />
            )}
          </button>
        </div>

        {/* Hover Overlay */}
        <div className="absolute inset-0 bg-gradient-to-t from-black/60 via-transparent to-transparent opacity-0 hover:opacity-100 transition-opacity">
          <div className="absolute bottom-3 left-3 right-3">
            <div className="text-white font-medium text-sm truncate">
              {file.originalName}
            </div>
            <div className="text-white/80 text-xs mt-1">
              {isVideo ? '🎥' : '📸'} {file.tags && file.tags.length > 0 ? file.tags[0] : 'Media'} • {formatFileSize(file.fileSize)}
              {isEncrypted && <> • AES-256</>}
            </div>
          </div>
          
          {/* Action Buttons */}
          <div className="absolute top-3 left-3 flex gap-2">
            <button
              className="p-2 bg-black/50 rounded hover:bg-black/70 transition-colors"
              onClick={(e) => {
                e.stopPropagation();
                // Toggle favorite
              }}
              title="Add to favorites"
            >
              <Heart className="w-4 h-4 text-white" />
            </button>
            <button
              className="p-2 bg-black/50 rounded hover:bg-black/70 transition-colors"
              onClick={(e) => {
                e.stopPropagation();
                // Download file
              }}
              title="Download"
            >
              <Download className="w-4 h-4 text-white" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// NOTE: Encryption keys are now passed securely via Authorization headers instead of URL query strings
