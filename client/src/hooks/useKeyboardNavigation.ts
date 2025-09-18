import { useState, useEffect, useCallback } from "react";
import type { MediaFile } from "@shared/schema";

export function useKeyboardNavigation(mediaFiles: MediaFile[]) {
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [isLightboxOpen, setIsLightboxOpen] = useState(false);

  const openLightbox = useCallback((index?: number) => {
    if (index !== undefined) {
      setSelectedIndex(index);
    }
    setIsLightboxOpen(true);
  }, []);

  const closeLightbox = useCallback(() => {
    setIsLightboxOpen(false);
  }, []);

  const navigateNext = useCallback(() => {
    if (mediaFiles.length === 0) return;
    setSelectedIndex(prev => (prev + 1) % mediaFiles.length);
  }, [mediaFiles.length]);

  const navigatePrevious = useCallback(() => {
    if (mediaFiles.length === 0) return;
    setSelectedIndex(prev => (prev - 1 + mediaFiles.length) % mediaFiles.length);
  }, [mediaFiles.length]);

  const navigateUp = useCallback(() => {
    if (!isLightboxOpen) {
      openLightbox();
    }
  }, [isLightboxOpen, openLightbox]);

  const navigateDown = useCallback(() => {
    if (isLightboxOpen) {
      closeLightbox();
    } else {
      navigateNext();
    }
  }, [isLightboxOpen, closeLightbox, navigateNext]);

  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    // Don't handle keyboard events if there are modal dialogs open
    const hasModalOpen = document.querySelector('[role="dialog"]');
    if (hasModalOpen && !isLightboxOpen) {
      return;
    }

    // Don't handle keyboard events if user is typing in an input
    const activeElement = document.activeElement;
    if (activeElement && (
      activeElement.tagName === 'INPUT' ||
      activeElement.tagName === 'TEXTAREA' ||
      activeElement.hasAttribute('contenteditable')
    )) {
      return;
    }

    switch (e.key.toLowerCase()) {
      case 'w':
      case 'arrowup':
        e.preventDefault();
        navigateUp();
        break;
        
      case 'a':
      case 'arrowleft':
        e.preventDefault();
        if (isLightboxOpen) {
          navigatePrevious();
        } else {
          navigatePrevious();
        }
        break;
        
      case 's':
      case 'arrowdown':
        e.preventDefault();
        navigateDown();
        break;
        
      case 'd':
      case 'arrowright':
        e.preventDefault();
        if (isLightboxOpen) {
          navigateNext();
        } else {
          navigateNext();
        }
        break;
        
      case 'escape':
        if (isLightboxOpen) {
          e.preventDefault();
          closeLightbox();
        }
        break;
        
      case 'enter':
      case ' ':
        if (!isLightboxOpen) {
          e.preventDefault();
          openLightbox();
        }
        break;
    }
  }, [
    isLightboxOpen,
    navigateUp,
    navigateDown,
    navigateNext,
    navigatePrevious,
    openLightbox,
    closeLightbox
  ]);

  useEffect(() => {
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [handleKeyDown]);

  // Reset selection when media files change
  useEffect(() => {
    if (mediaFiles.length === 0) {
      setSelectedIndex(0);
    } else if (selectedIndex >= mediaFiles.length) {
      setSelectedIndex(mediaFiles.length - 1);
    }
  }, [mediaFiles.length, selectedIndex]);

  return {
    selectedIndex,
    isLightboxOpen,
    openLightbox,
    closeLightbox,
    navigateNext,
    navigatePrevious,
    setSelectedIndex,
  };
}
