import { useEffect, useState } from "react";

export default function KeyboardNavigation() {
  const [showHints, setShowHints] = useState(false);

  useEffect(() => {
    // Show keyboard hints after 3 seconds
    const timer = setTimeout(() => {
      setShowHints(true);
    }, 3000);

    // Hide hints after 10 seconds
    const hideTimer = setTimeout(() => {
      setShowHints(false);
    }, 13000);

    return () => {
      clearTimeout(timer);
      clearTimeout(hideTimer);
    };
  }, []);

  const toggleHints = () => {
    setShowHints(!showHints);
  };

  return (
    <>
      {/* Toggle Button */}
      <button
        className="fixed bottom-6 left-6 bg-card/90 backdrop-blur-lg border border-border rounded-lg p-3 text-sm hover:bg-card transition-colors z-40"
        onClick={toggleHints}
        title="Keyboard Shortcuts"
        data-testid="keyboard-shortcuts-toggle"
      >
        ⌨️
      </button>

      {/* Keyboard Hints Panel */}
      {showHints && (
        <div 
          className="fixed bottom-6 right-6 bg-card/90 backdrop-blur-lg border border-border rounded-lg p-4 text-sm max-w-xs z-40"
          data-testid="keyboard-hints"
        >
          <div className="font-semibold text-foreground mb-3 flex items-center gap-2">
            ⌨️ Keyboard Navigation
            <button 
              onClick={() => setShowHints(false)}
              className="ml-auto text-muted-foreground hover:text-foreground"
            >
              ×
            </button>
          </div>
          
          <div className="space-y-2 text-muted-foreground">
            <div className="font-semibold text-xs text-foreground mb-1">Gallery Navigation</div>
            <div className="flex justify-between">
              <span>Navigate thumbnails</span>
              <div className="flex gap-1">
                <kbd className="px-2 py-1 bg-secondary rounded text-xs">↑↓←→</kbd>
              </div>
            </div>
            
            <div className="flex justify-between">
              <span>Open viewer</span>
              <div className="flex gap-1">
                <kbd className="px-2 py-1 bg-secondary rounded text-xs">Enter</kbd>
                <kbd className="px-2 py-1 bg-secondary rounded text-xs">Space</kbd>
              </div>
            </div>
            
            <hr className="border-border my-2" />
            <div className="font-semibold text-xs text-foreground mb-1">Viewer Controls</div>
            
            <div className="flex justify-between">
              <span>Previous/Next</span>
              <kbd className="px-2 py-1 bg-secondary rounded text-xs">←→</kbd>
            </div>
            
            <div className="flex justify-between">
              <span>Zoom in/out</span>
              <kbd className="px-2 py-1 bg-secondary rounded text-xs">↑↓</kbd>
            </div>
            
            <div className="flex justify-between">
              <span>Toggle fullscreen</span>
              <kbd className="px-2 py-1 bg-secondary rounded text-xs">F</kbd>
            </div>
            
            <div className="flex justify-between">
              <span>Rotate image</span>
              <kbd className="px-2 py-1 bg-secondary rounded text-xs">R</kbd>
            </div>
            
            <div className="flex justify-between">
              <span>Play/Pause video</span>
              <kbd className="px-2 py-1 bg-secondary rounded text-xs">Space</kbd>
            </div>
            
            <div className="flex justify-between">
              <span>Close viewer</span>
              <kbd className="px-2 py-1 bg-secondary rounded text-xs">ESC</kbd>
            </div>
          </div>
          
          <div className="mt-3 pt-2 border-t border-border text-xs text-muted-foreground">
            Intuitive keyboard shortcuts for efficient media browsing
          </div>
        </div>
      )}
    </>
  );
}
