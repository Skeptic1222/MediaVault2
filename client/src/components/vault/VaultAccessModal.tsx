import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Shield, Lock, Eye, EyeOff, Fingerprint } from "lucide-react";

interface VaultAccessModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAuthenticate: (passphrase: string) => void;
  onSetup: (passphrase: string) => void;
  isAuthenticating?: boolean;
  isSettingUp?: boolean;
  mode?: 'authenticate' | 'setup';
}

export default function VaultAccessModal({
  isOpen,
  onClose,
  onAuthenticate,
  onSetup,
  isAuthenticating = false,
  isSettingUp = false,
  mode = 'authenticate'
}: VaultAccessModalProps) {
  const [passphrase, setPassphrase] = useState('');
  const [confirmPassphrase, setConfirmPassphrase] = useState('');
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [useBiometric, setUseBiometric] = useState(false);
  const [currentMode, setCurrentMode] = useState(mode);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    if (currentMode === 'setup') {
      if (passphrase !== confirmPassphrase) {
        return; // Show error in real implementation
      }
      if (passphrase.length < 8) {
        return; // Show error in real implementation
      }
      onSetup(passphrase);
    } else {
      onAuthenticate(passphrase);
    }
  };

  const handleClose = () => {
    setPassphrase('');
    setConfirmPassphrase('');
    setShowPassphrase(false);
    setCurrentMode(mode);
    onClose();
  };

  const isFormValid = currentMode === 'setup' 
    ? passphrase.length >= 8 && passphrase === confirmPassphrase
    : passphrase.length > 0;

  return (
    <Dialog open={isOpen} onOpenChange={handleClose}>
      <DialogContent className="max-w-md" data-testid="vault-access-modal">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-3 text-center justify-center">
            <div className="w-12 h-12 bg-accent/20 rounded-full flex items-center justify-center">
              <Shield className="w-6 h-6 text-accent" />
            </div>
            <div>
              <div className="text-xl font-bold">
                {currentMode === 'setup' ? 'Setup Vault' : 'Vault Access'}
              </div>
              <div className="text-sm font-normal text-muted-foreground">
                {currentMode === 'setup' 
                  ? 'Create a secure passphrase for your vault'
                  : 'Enter your vault passphrase to access encrypted content'
                }
              </div>
            </div>
          </DialogTitle>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Passphrase Input */}
          <div className="space-y-2">
            <Label htmlFor="passphrase">
              {currentMode === 'setup' ? 'Create Passphrase' : 'Vault Passphrase'}
            </Label>
            <div className="relative">
              <Input
                id="passphrase"
                type={showPassphrase ? 'text' : 'password'}
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder={currentMode === 'setup' ? 'Enter a strong passphrase...' : 'Enter passphrase'}
                className="pr-10"
                autoComplete="off"
                data-testid="passphrase-input"
              />
              <button
                type="button"
                className="absolute right-3 top-1/2 transform -translate-y-1/2 text-muted-foreground hover:text-foreground"
                onClick={() => setShowPassphrase(!showPassphrase)}
              >
                {showPassphrase ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            {currentMode === 'setup' && (
              <div className="text-xs text-muted-foreground">
                Minimum 8 characters. Use a mix of letters, numbers, and symbols.
              </div>
            )}
          </div>

          {/* Confirm Passphrase (Setup Mode) */}
          {currentMode === 'setup' && (
            <div className="space-y-2">
              <Label htmlFor="confirm-passphrase">Confirm Passphrase</Label>
              <div className="relative">
                <Input
                  id="confirm-passphrase"
                  type={showPassphrase ? 'text' : 'password'}
                  value={confirmPassphrase}
                  onChange={(e) => setConfirmPassphrase(e.target.value)}
                  placeholder="Confirm your passphrase"
                  className="pr-10"
                  autoComplete="off"
                  data-testid="confirm-passphrase-input"
                />
                <button
                  type="button"
                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  onClick={() => setShowPassphrase(!showPassphrase)}
                >
                  {showPassphrase ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {confirmPassphrase && passphrase !== confirmPassphrase && (
                <div className="text-xs text-destructive">
                  Passphrases do not match
                </div>
              )}
            </div>
          )}

          {/* Biometric Option */}
          <div className="flex items-center space-x-3">
            <Checkbox
              id="biometric"
              checked={useBiometric}
              onCheckedChange={(checked) => setUseBiometric(checked as boolean)}
              data-testid="biometric-checkbox"
            />
            <Label htmlFor="biometric" className="flex items-center gap-2 text-sm">
              <Fingerprint className="w-4 h-4" />
              Use biometric authentication (if available)
            </Label>
          </div>

          {/* Security Information */}
          <div className="bg-muted/50 rounded-lg p-3 text-xs text-muted-foreground">
            <div className="font-semibold mb-2 text-foreground">🔒 Security Features:</div>
            <ul className="space-y-1">
              <li>• AES-256-GCM encryption</li>
              <li>• Zero-knowledge architecture</li>
              <li>• Client-side key derivation</li>
              <li>• Secure session management</li>
            </ul>
          </div>

          {/* Action Buttons */}
          <div className="flex space-x-3 pt-4">
            <Button
              type="button"
              variant="outline"
              className="flex-1"
              onClick={handleClose}
              disabled={isAuthenticating || isSettingUp}
              data-testid="cancel-button"
            >
              Cancel
            </Button>
            
            <Button
              type="submit"
              className="flex-1 bg-accent hover:bg-accent/90"
              disabled={!isFormValid || isAuthenticating || isSettingUp}
              data-testid="submit-button"
            >
              {isAuthenticating || isSettingUp ? (
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                  {currentMode === 'setup' ? 'Setting up...' : 'Authenticating...'}
                </div>
              ) : (
                <>
                  <Lock className="w-4 h-4 mr-2" />
                  {currentMode === 'setup' ? 'Create Vault' : 'Unlock Vault'}
                </>
              )}
            </Button>
          </div>

          {/* Mode Toggle */}
          {currentMode === 'authenticate' && (
            <div className="text-center pt-2 border-t border-border">
              <button
                type="button"
                className="text-sm text-muted-foreground hover:text-foreground transition-colors"
                onClick={() => setCurrentMode('setup')}
                data-testid="setup-vault-link"
              >
                Don't have a vault? Set up vault access
              </button>
            </div>
          )}
          
          {currentMode === 'setup' && (
            <div className="text-center pt-2 border-t border-border">
              <button
                type="button"
                className="text-sm text-muted-foreground hover:text-foreground transition-colors"
                onClick={() => setCurrentMode('authenticate')}
                data-testid="authenticate-vault-link"
              >
                Already have a vault? Sign in to vault
              </button>
            </div>
          )}
        </form>
      </DialogContent>
    </Dialog>
  );
}
