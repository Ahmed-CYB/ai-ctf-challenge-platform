import { useState, useEffect } from 'react';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Card } from '../ui/card';
import { Label } from '../ui/label';
import { Terminal, Lock, Mail, HelpCircle } from 'lucide-react';
import { login } from '../../services/auth';
import { toast } from 'sonner';
import { WelcomeGuide } from '../WelcomeGuide';

interface LoginProps {
  onLoginSuccess: () => void;
  onSwitchToSignUp: () => void;
}

export function Login({ onLoginSuccess, onSwitchToSignUp }: LoginProps) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [showGuide, setShowGuide] = useState(false);

  // Show guide on first visit
  useEffect(() => {
    const hasSeenGuide = localStorage.getItem('ctf-has-seen-guide');
    if (!hasSeenGuide) {
      setShowGuide(true);
      localStorage.setItem('ctf-has-seen-guide', 'true');
    }
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!email || !password) {
      toast.error('Please enter both email and password');
      return;
    }

    setIsLoading(true);

    const result = await login(email, password);

    if (result.success && result.user) {
      toast.success(`Welcome back, ${result.user.name}!`);
      onLoginSuccess();
    } else {
      toast.error(result.error || 'Invalid credentials');
    }

    setIsLoading(false);
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
          <h1 className="mb-2 terminal-text">CTF Platform</h1>
          <p className="text-primary">AI-Powered Challenge Generation</p>
          
          {/* Help Button */}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setShowGuide(true)}
            className="mt-2 text-muted-foreground hover:text-primary"
          >
            <HelpCircle className="w-4 h-4 mr-2" />
            Need Help?
          </Button>
        </div>

        {/* Login Card */}
        <Card className="p-8 cyber-gradient relative z-20">
          <div className="mb-6">
            <h2 className="mb-2">Welcome Back</h2>
            <p className="text-muted-foreground">Sign in to your account to continue</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
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
                />
              </div>
            </div>

            <Button type="submit" className="w-full relative z-30" disabled={isLoading}>
              {isLoading ? 'Signing in...' : 'Sign In'}
            </Button>
          </form>

          <p className="text-center text-muted-foreground mt-6">
            Don't have an account?{' '}
            <button
              type="button"
              className="text-primary hover:underline font-medium relative z-30"
              onClick={onSwitchToSignUp}
            >
              Sign up here
            </button>
          </p>
        </Card>

        {/* Helpful Note */}
        <div className="mt-4 p-4 bg-muted/50 rounded-lg border border-border relative z-20">
          <p className="text-center text-muted-foreground">
            <strong>New user?</strong> You need to create an account first by clicking "Sign up here" above.
          </p>
        </div>
      </div>

      {/* Welcome Guide Dialog */}
      <WelcomeGuide open={showGuide} onClose={() => setShowGuide(false)} />
    </div>
  );
}
