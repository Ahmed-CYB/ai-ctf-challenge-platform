/**
 * Avatar Selector Dialog
 * Popup dialog for selecting animal avatars
 */

import { useState } from 'react';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from './ui/dialog';
import { Button } from './ui/button';
import { ANIMAL_AVATARS, getAnimalById } from '../utils/animalAvatars';
import { AnimalAvatar } from './AnimalAvatar';
import { Loader2, Image } from 'lucide-react';

interface AvatarSelectorDialogProps {
  open: boolean;
  onClose: () => void;
  currentAvatar: string;
  onConfirm: (animalId: string) => Promise<void>;
}

export function AvatarSelectorDialog({ 
  open, 
  onClose, 
  currentAvatar,
  onConfirm 
}: AvatarSelectorDialogProps) {
  const [selectedAvatar, setSelectedAvatar] = useState(currentAvatar);
  const [isLoading, setIsLoading] = useState(false);

  const handleConfirm = async () => {
    console.log('Confirm button clicked!', { selectedAvatar, currentAvatar });
    
    if (selectedAvatar === currentAvatar) {
      console.log('Same avatar selected, just closing');
      onClose();
      return;
    }

    setIsLoading(true);
    console.log('Starting avatar update...');
    try {
      await onConfirm(selectedAvatar);
      console.log('Avatar update successful!');
      onClose();
    } catch (error) {
      console.error('Failed to update avatar:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const selectedAnimal = getAnimalById(selectedAvatar);

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-3xl cyber-gradient p-6 gap-4 max-h-[90vh] overflow-hidden">
        {/* Header */}
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Image className="w-5 h-5 text-primary" />
            Choose Your Avatar Animal
          </DialogTitle>
          <DialogDescription>
            Select an animal that represents your personality
          </DialogDescription>
        </DialogHeader>

        {/* Preview Section */}
        <div className="flex items-center gap-4 p-4 bg-muted/30 rounded-lg border border-border">
          <AnimalAvatar animalId={selectedAvatar} size={80} />
          <div className="flex-1">
            <h3 className="text-primary">{selectedAnimal?.name}</h3>
            <p className="text-muted-foreground">
              {selectedAvatar === currentAvatar ? 'Currently selected' : 'New selection'}
            </p>
          </div>
        </div>

        {/* Animal Grid - Scrollable */}
        <div className="overflow-y-auto custom-scrollbar max-h-[40vh] -mx-2 px-2">
          <div className="grid grid-cols-4 sm:grid-cols-6 md:grid-cols-8 gap-3">
            {ANIMAL_AVATARS.map((animal) => (
              <button
                key={animal.id}
                type="button"
                onClick={() => setSelectedAvatar(animal.id)}
                disabled={isLoading}
                className={`
                  group relative p-3 rounded-lg transition-all duration-200 
                  flex flex-col items-center gap-2 hover:shadow-lg
                  ${selectedAvatar === animal.id 
                    ? 'bg-accent ring-2 ring-primary glow-primary-sm scale-105 shadow-lg' 
                    : 'bg-muted/40 hover:bg-accent hover:scale-105'
                  }
                  ${isLoading ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
                  ${animal.id === currentAvatar && animal.id !== selectedAvatar ? 'ring-1 ring-muted-foreground/30' : ''}
                `}
                title={animal.name}
              >
                <AnimalAvatar 
                  animalId={animal.id} 
                  size={40} 
                  showBackground={false}
                  className="group-hover:scale-110 transition-transform"
                />
                <span className="text-xs text-center text-muted-foreground group-hover:text-foreground transition-colors">
                  {animal.name}
                </span>
                
                {/* Current indicator */}
                {animal.id === currentAvatar && (
                  <div className="absolute -top-1 -right-1 w-4 h-4 bg-primary rounded-full border-2 border-background">
                    <div className="w-full h-full rounded-full bg-primary animate-ping opacity-75"></div>
                  </div>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* Footer */}
        <DialogFooter className="flex-col sm:flex-row gap-2 border-t border-border pt-4">
          <p className="text-sm text-muted-foreground flex-1 self-center">
            {ANIMAL_AVATARS.length} animals available
          </p>
          <div className="flex gap-2 w-full sm:w-auto justify-end">
            <Button
              type="button"
              variant="outline"
              onClick={onClose}
              disabled={isLoading}
            >
              Cancel
            </Button>
            <Button
              type="button"
              onClick={() => {
                console.log('Button clicked!');
                handleConfirm();
              }}
              disabled={isLoading}
              className="glow-primary-sm relative z-10 pointer-events-auto"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Saving...
                </>
              ) : selectedAvatar === currentAvatar ? (
                'Close'
              ) : (
                'Confirm Selection'
              )}
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
