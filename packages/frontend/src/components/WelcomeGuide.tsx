/**
 * Welcome Guide Component
 * Shows helpful tips for new users
 */

import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from './ui/dialog';
import { Button } from './ui/button';
import { Terminal, User, Lock, Mail } from 'lucide-react';

interface WelcomeGuideProps {
  open: boolean;
  onClose: () => void;
}

export function WelcomeGuide({ open, onClose }: WelcomeGuideProps) {
  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <div className="flex items-center gap-3 mb-2">
            <div className="bg-primary text-primary-foreground p-2 rounded-lg">
              <Terminal className="w-6 h-6" />
            </div>
            <DialogTitle>Welcome to CTF Platform! 🚀</DialogTitle>
          </div>
          <DialogDescription>
            Your AI-powered cybersecurity challenge generation platform
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 mt-4">
          <div className="p-4 bg-muted/30 rounded-lg border border-border">
            <h3 className="flex items-center gap-2 mb-2">
              <User className="w-5 h-5 text-primary" />
              Getting Started
            </h3>
            <ul className="space-y-2 text-sm text-muted-foreground ml-7">
              <li>✅ <strong>New User:</strong> Click "Sign up" to create an account</li>
              <li>✅ <strong>Choose Avatar:</strong> Select an animal that represents you</li>
              <li>✅ <strong>Username:</strong> Must be unique (3-20 characters)</li>
              <li>✅ <strong>Password:</strong> At least 8 characters with special symbols</li>
            </ul>
          </div>

          <div className="p-4 bg-muted/30 rounded-lg border border-border">
            <h3 className="flex items-center gap-2 mb-2">
              <Lock className="w-5 h-5 text-chart-2" />
              Common Issues
            </h3>
            <ul className="space-y-2 text-sm text-muted-foreground ml-7">
              <li>⚠️ <strong>"Username already taken":</strong> Try a different username</li>
              <li>⚠️ <strong>"Invalid credentials":</strong> Check your email and password</li>
              <li>⚠️ <strong>"Email already registered":</strong> Use login instead</li>
            </ul>
          </div>

          <div className="p-4 bg-primary/10 rounded-lg border border-primary/20">
            <h3 className="flex items-center gap-2 mb-2 text-primary">
              <Mail className="w-5 h-5" />
              Pro Tip
            </h3>
            <p className="text-sm text-muted-foreground ml-7">
              Each animal avatar is unique to you! You can change it anytime from your profile settings.
              There are {24} different animals to choose from! 🦁🦊🦉
            </p>
          </div>
        </div>

        <div className="flex justify-end mt-6">
          <Button onClick={onClose} className="glow-primary-sm">
            Got it, let's start!
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
