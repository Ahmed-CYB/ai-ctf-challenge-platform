import { useState } from 'react';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Card } from '../ui/card';
import { Label } from '../ui/label';
import { Terminal, Lock, Mail, User } from 'lucide-react';
import { register } from '../../services/auth';
import { toast } from 'sonner';
import { ANIMAL_AVATARS, getRandomAnimal } from '../../utils/animalAvatars';
import { AnimalAvatar } from '../AnimalAvatar';

interface SignUpProps {
  onSignUpSuccess: () => void;
  onSwitchToLogin: () => void;
}

export function SignUp({ onSignUpSuccess, onSwitchToLogin }: SignUpProps) {
  const [name, setName] = useState('');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [selectedAvatar, setSelectedAvatar] = useState(getRandomAnimal().id);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    // Validate form
    if (!name || !username || !email || !password || !confirmPassword) {
      toast.error('Please fill in all fields');
      return;
    }

    // Validate username format
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      toast.error('Username must be 3-20 characters and contain only letters, numbers, and underscores');
      return;
    }

    if (password !== confirmPassword) {
      toast.error('Passwords do not match');
      return;
    }

    setIsLoading(true);

    try {
      console.log('Starting registration for:', username, email);
      const result = await register(username, email, password, name, selectedAvatar);
      console.log('Registration result:', result);

      if (result.success) {
        toast.success('🎉 Account created successfully! Please log in.');
        setTimeout(() => {
          onSwitchToLogin();
        }, 1000);
      } else {
        console.error('Registration failed:', result.error);
        // Provide helpful error messages
        if (result.error?.toLowerCase().includes('username')) {
          toast.error('⚠️ Username already taken. Please try a different one.');
        } else if (result.error?.toLowerCase().includes('email')) {
          toast.error('⚠️ Email already registered. Try logging in instead.');
        } else {
          toast.error(result.error || 'Registration failed. Please try again.');
        }
      }
    } catch (error) {
      console.error('Registration exception:', error);
      toast.error('An unexpected error occurred. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-background relative overflow-hidden">
      {/* Cybersecurity background effect */}
      <div className="absolute inset-0 opacity-10 pointer-events-none">
        <div className="absolute top-20 left-20 w-72 h-72 bg-primary rounded-full blur-[100px]"></div>
        <div className="absolute bottom-20 right-20 w-96 h-96 bg-info rounded-full blur-[120px]"></div>
      </div>
      
      {/* Grid Pattern */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,rgba(0,255,136,0.05)_1px,transparent_1px),linear-gradient(to_bottom,rgba(0,255,136,0.05)_1px,transparent_1px)] bg-[size:24px_24px] pointer-events-none" />

      <div className="w-full max-w-md relative z-10">
        {/* Logo/Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-primary text-primary-foreground mb-4 glow-primary">
            <Terminal className="w-8 h-8" />
          </div>
          <h1 className="mb-2 terminal-text">Create Account</h1>
          <p className="text-primary">Join the CTF Platform community</p>
        </div>

        {/* Sign Up Card */}
        <Card className="p-8 cyber-gradient relative z-20">
          <div className="mb-6">
            <h2 className="mb-2">Sign Up</h2>
            <p className="text-muted-foreground">Create your account to get started</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Avatar Selection */}
            <div className="space-y-2">
              <Label>Choose Your Avatar</Label>
              <div className="flex items-center gap-4 p-4 bg-muted/30 rounded-lg border border-border">
                <AnimalAvatar animalId={selectedAvatar} size={64} />
                <div className="flex-1">
                  <p className="text-muted-foreground mb-2">
                    Pick an animal that represents you
                  </p>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => setSelectedAvatar(getRandomAnimal().id)}
                    disabled={isLoading}
                  >
                    Random Animal
                  </Button>
                </div>
              </div>
              <div className="grid grid-cols-6 gap-2 max-h-40 overflow-y-auto p-2 bg-muted/20 rounded custom-scrollbar">
                {ANIMAL_AVATARS.map((animal) => (
                  <button
                    key={animal.id}
                    type="button"
                    onClick={() => setSelectedAvatar(animal.id)}
                    title={animal.name}
                    className={`p-2 rounded hover:bg-accent transition-all duration-200 ${
                      selectedAvatar === animal.id ? 'bg-accent ring-2 ring-primary glow-primary-sm' : ''
                    }`}
                    disabled={isLoading}
                  >
                    <AnimalAvatar animalId={animal.id} size={32} showBackground={false} />
                  </button>
                ))}
              </div>
              <p className="text-xs text-muted-foreground text-center">
                {ANIMAL_AVATARS.length} animals available • Scroll to see more
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="name">Full Name</Label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
                <Input
                  id="name"
                  type="text"
                  placeholder="Ahmed Omer"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="pl-10"
                  disabled={isLoading}
                  required
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="username">Username</Label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
                <Input
                  id="username"
                  type="text"
                  placeholder="ahmed_omer"
                  value={username}
                  onChange={(e) => setUsername(e.target.value.toLowerCase())}
                  className="pl-10"
                  disabled={isLoading}
                  required
                  pattern="[a-zA-Z0-9_]{3,20}"
                />
              </div>
              <p className="text-muted-foreground">3-20 characters, letters, numbers, and underscores only</p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
                <Input
                  id="email"
                  type="email"
                  placeholder="you@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="pl-10"
                  disabled={isLoading}
                  required
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
                <Input
                  id="password"
                  type="password"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="pl-10"
                  disabled={isLoading}
                  required
                  minLength={8}
                />
              </div>
              <p className="text-muted-foreground">Must be at least 8 characters with special characters (!@#$%...)</p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="confirmPassword">Confirm Password</Label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
                <Input
                  id="confirmPassword"
                  type="password"
                  placeholder="••••••••"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="pl-10"
                  disabled={isLoading}
                  required
                  minLength={8}
                />
              </div>
            </div>

            <Button type="submit" className="w-full relative z-30" disabled={isLoading}>
              {isLoading ? 'Creating Account...' : 'Create Account'}
            </Button>
          </form>

          <p className="text-center text-muted-foreground mt-6">
            Already have an account?{' '}
            <button
              type="button"
              className="text-primary hover:underline relative z-30"
              onClick={onSwitchToLogin}
            >
              Sign in
            </button>
          </p>
        </Card>

        {/* Footer Note */}
        <p className="text-center text-muted-foreground mt-6 relative z-20">
          By signing up, you agree to our Terms of Service and Privacy Policy
        </p>
      </div>
    </div>
  );
}
