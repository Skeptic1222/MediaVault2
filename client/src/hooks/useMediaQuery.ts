import { useState, useEffect } from 'react';

export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState<boolean>(false);

  useEffect(() => {
    const mediaQuery = window.matchMedia(query);
    
    // Set initial value
    setMatches(mediaQuery.matches);
    
    // Define handler
    const handler = (event: MediaQueryListEvent) => {
      setMatches(event.matches);
    };
    
    // Add listener
    if (mediaQuery.addEventListener) {
      mediaQuery.addEventListener('change', handler);
    } else {
      // Fallback for older browsers
      mediaQuery.addListener(handler);
    }
    
    // Cleanup
    return () => {
      if (mediaQuery.removeEventListener) {
        mediaQuery.removeEventListener('change', handler);
      } else {
        // Fallback for older browsers
        mediaQuery.removeListener(handler);
      }
    };
  }, [query]);

  return matches;
}

// Common breakpoint hooks
export const useIsDesktop = () => useMediaQuery('(min-width: 1024px)');
export const useIsTablet = () => useMediaQuery('(min-width: 768px) and (max-width: 1023px)');
export const useIsMobile = () => useMediaQuery('(max-width: 767px)');

// More specific breakpoints
export const useIsSmallScreen = () => useMediaQuery('(max-width: 640px)');
export const useIsLargeScreen = () => useMediaQuery('(min-width: 1280px)');
export const useIsXLScreen = () => useMediaQuery('(min-width: 1536px)');

// Orientation queries
export const useIsLandscape = () => useMediaQuery('(orientation: landscape)');
export const useIsPortrait = () => useMediaQuery('(orientation: portrait)');

// Accessibility queries
export const usePrefersReducedMotion = () => useMediaQuery('(prefers-reduced-motion: reduce)');
export const usePrefersDarkScheme = () => useMediaQuery('(prefers-color-scheme: dark)');
export const usePrefersLightScheme = () => useMediaQuery('(prefers-color-scheme: light)');

// High resolution display detection
export const useIsHighDPI = () => useMediaQuery('(min-resolution: 2dppx)');

// Touch device detection
export const useIsTouchDevice = () => useMediaQuery('(hover: none) and (pointer: coarse)');

// Print media query
export const useIsPrintMode = () => useMediaQuery('print');
