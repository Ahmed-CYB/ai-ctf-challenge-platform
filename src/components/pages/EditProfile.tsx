import { useState, useEffect } from 'react';
import { Card } from '../ui/card';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Textarea } from '../ui/textarea';
import { Avatar, AvatarFallback, AvatarImage } from '../ui/avatar';
import { ArrowLeft, Save, Loader2, Eye, EyeOff, Check, X, Image } from 'lucide-react';
import { getCurrentUser } from '../../services/auth';
import type { User } from '../../services/auth';
import { toast } from 'sonner';
import { Separator } from '../ui/separator';
import { ANIMAL_AVATARS } from '../../utils/animalAvatars';
import { AnimalAvatar } from '../AnimalAvatar';
import { AvatarSelectorDialog } from '../AvatarSelectorDialog';

interface EditProfileProps {
  onBack: () => void;
  onSaved?: () => void;
}

export function EditProfile({ onBack, onSaved }: EditProfileProps) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(false);
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [showAvatarSelector, setShowAvatarSelector] = useState(false);

  // Form state
  const [fullName, setFullName] = useState('');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('');
  const [bio, setBio] = useState('');
  const [selectedAvatar, setSelectedAvatar] = useState('lion');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  // Password validation state
  const [passwordValidation, setPasswordValidation] = useState({
    minLength: false,
    hasSpecialChar: false,
    hasNumber: false,
    hasUpperCase: false,
    hasLowerCase: false,
  });

  useEffect(() => {
    const loadUser = async () => {
      const currentUser = await getCurrentUser();
      if (currentUser) {
        setUser(currentUser);
        setFullName(currentUser.name || '');
        setUsername(currentUser.username || '');
        setEmail(currentUser.email || '');
        setRole(currentUser.role || '');
        setBio(currentUser.bio || '');
        setSelectedAvatar(currentUser.avatar || 'lion');
      }
    };
    loadUser();
  }, []);

  // Validate password in real-time
  useEffect(() => {
    if (newPassword) {
      setPasswordValidation({
        minLength: newPassword.length >= 8,
        hasSpecialChar: /[!@#$%^&*(),.?":{}|<>]/.test(newPassword),
        hasNumber: /\d/.test(newPassword),
        hasUpperCase: /[A-Z]/.test(newPassword),
        hasLowerCase: /[a-z]/.test(newPassword),
      });
    }
  }, [newPassword]);

  const isPasswordValid = () => {
    return Object.values(passwordValidation).every(v => v);
  };

  const handleSave = async () => {
    // Validation
    if (!fullName.trim()) {
      toast.error('Full name is required');
      return;
    }

    if (!username.trim()) {
      toast.error('Username is required');
      return;
    }

    if (username.length < 3) {
      toast.error('Username must be at least 3 characters');
      return;
    }

    if (!email.trim()) {
      toast.error('Email is required');
      return;
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      toast.error('Please enter a valid email address');
      return;
    }

    // Password change validation
    if (newPassword || confirmPassword) {
      if (!currentPassword) {
        toast.error('Current password is required to change password');
        return;
      }

      if (!newPassword) {
        toast.error('New password is required');
        return;
      }

      if (!isPasswordValid()) {
        toast.error('New password does not meet all requirements');
        return;
      }

      if (newPassword !== confirmPassword) {
        toast.error('New passwords do not match');
        return;
      }
    }

    setLoading(true);

    try {
      const token = localStorage.getItem('token');
      const response = await fetch(
        `http://localhost:3002/api/users/${user?.user_id}`,
        {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
          },
          body: JSON.stringify({
            fullName,
            username: username.toLowerCase(),
            email: email.toLowerCase(),
            role,
            bio,
            avatar: selectedAvatar,
            currentPassword: currentPassword || undefined,
            newPassword: newPassword || undefined,
          }),
        }
      );

      const result = await response.json();

      if (!response.ok) {
        toast.error(result.error || 'Failed to update profile');
        return;
      }

      toast.success('Profile updated successfully!');
      
      // Clear password fields
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');

      // Wait a moment to ensure server has updated
      await new Promise(resolve => setTimeout(resolve, 500));

      // Force refresh session to get the latest user data
      const updatedUser = await getCurrentUser(true);
      if (updatedUser) {
        setUser(updatedUser);
        setFullName(updatedUser.name || '');
        setUsername(updatedUser.username || '');
        setEmail(updatedUser.email || '');
        setRole(updatedUser.role || '');
        setBio(updatedUser.bio || '');
        setSelectedAvatar(updatedUser.avatar || 'lion');
      }

      // Navigate back and trigger profile refresh
      setTimeout(() => {
        if (onSaved) {
          onSaved(); // This will refresh the Profile page
        } else {
          onBack();
        }
      }, 800);
    } catch (error) {
      console.error('Update profile error:', error);
      toast.error('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const PasswordRequirement = ({ met, text }: { met: boolean; text: string }) => (
    <div className="flex items-center gap-2 text-sm">
      {met ? (
        <Check className="w-4 h-4 text-green-600" />
      ) : (
        <X className="w-4 h-4 text-muted-foreground" />
      )}
      <span className={met ? 'text-green-600' : 'text-muted-foreground'}>{text}</span>
    </div>
  );

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" onClick={onBack}>
          <ArrowLeft className="w-5 h-5" />
        </Button>
        <div>
          <h1>Edit Profile</h1>
          <p className="text-muted-foreground">Update your account information and settings</p>
        </div>
      </div>

      <Card className="p-6 space-y-6">
        {/* Animal Avatar Selection */}
        <div className="space-y-4">
          <Label>Profile Avatar</Label>
          <div className="flex items-center gap-4 p-4 bg-muted/30 rounded-lg border border-border">
            {/* Avatar Display (not clickable) */}
            <AnimalAvatar animalId={selectedAvatar} size={80} />
            <div className="flex-1">
              <p className="text-muted-foreground mb-2">
                Choose from {ANIMAL_AVATARS.length} different animals to represent you
              </p>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setShowAvatarSelector(true)}
              >
                <Image className="w-4 h-4 mr-2" />
                Change Avatar
              </Button>
            </div>
          </div>
        </div>

        <Separator />

        {/* Basic Information */}
        <div className="space-y-4">
          <h3>Basic Information</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="fullName">Full Name *</Label>
              <Input
                id="fullName"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                placeholder="Enter your full name"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="username">Username *</Label>
              <Input
                id="username"
                value={username}
                onChange={(e) => setUsername(e.target.value.toLowerCase().replace(/\s/g, '_'))}
                placeholder="Enter username"
              />
              <p className="text-xs text-muted-foreground">
                Lowercase letters, numbers, and underscores only
              </p>
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="email">Email Address *</Label>
            <Input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Enter your email"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="role">Role / Job Title</Label>
            <Input
              id="role"
              value={role}
              onChange={(e) => setRole(e.target.value)}
              placeholder="e.g., Security Researcher, Student, CTF Player"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="bio">Bio / Description</Label>
            <Textarea
              id="bio"
              value={bio}
              onChange={(e) => setBio(e.target.value)}
              placeholder="Tell us about yourself..."
              rows={4}
              maxLength={500}
            />
            <p className="text-xs text-muted-foreground text-right">
              {bio.length}/500 characters
            </p>
          </div>
        </div>

        <Separator />

        {/* Change Password Section */}
        <div className="space-y-4">
          <div>
            <h3>Change Password</h3>
            <p className="text-sm text-muted-foreground">Leave blank if you don't want to change your password</p>
          </div>

          <div className="space-y-2">
            <Label htmlFor="currentPassword">Current Password</Label>
            <div className="relative">
              <Input
                id="currentPassword"
                type={showCurrentPassword ? 'text' : 'password'}
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                placeholder="Enter current password"
              />
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="absolute right-2 top-1/2 -translate-y-1/2"
                onClick={() => setShowCurrentPassword(!showCurrentPassword)}
              >
                {showCurrentPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </Button>
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="newPassword">New Password</Label>
            <div className="relative">
              <Input
                id="newPassword"
                type={showNewPassword ? 'text' : 'password'}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="Enter new password"
              />
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="absolute right-2 top-1/2 -translate-y-1/2"
                onClick={() => setShowNewPassword(!showNewPassword)}
              >
                {showNewPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </Button>
            </div>
            
            {/* Password Requirements */}
            {newPassword && (
              <div className="mt-3 space-y-2 p-3 bg-muted/50 rounded-lg">
                <p className="text-sm font-medium">Password Requirements:</p>
                <PasswordRequirement met={passwordValidation.minLength} text="At least 8 characters" />
                <PasswordRequirement met={passwordValidation.hasUpperCase} text="At least one uppercase letter (A-Z)" />
                <PasswordRequirement met={passwordValidation.hasLowerCase} text="At least one lowercase letter (a-z)" />
                <PasswordRequirement met={passwordValidation.hasNumber} text="At least one number (0-9)" />
                <PasswordRequirement met={passwordValidation.hasSpecialChar} text="At least one special character (!@#$%^&*)" />
              </div>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="confirmPassword">Confirm New Password</Label>
            <div className="relative">
              <Input
                id="confirmPassword"
                type={showConfirmPassword ? 'text' : 'password'}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Confirm new password"
              />
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="absolute right-2 top-1/2 -translate-y-1/2"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
              >
                {showConfirmPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </Button>
            </div>
            {confirmPassword && newPassword !== confirmPassword && (
              <p className="text-sm text-destructive">Passwords do not match</p>
            )}
          </div>
        </div>

        <Separator />

        {/* Password Policy Information */}
        <div className="bg-muted/50 p-4 rounded-lg space-y-2">
          <h4 className="flex items-center gap-2">
            <span>🔒</span> Security & Privacy Policy
          </h4>
          <ul className="text-sm text-muted-foreground space-y-1 list-disc list-inside">
            <li>Your password is encrypted and securely stored</li>
            <li>We never share your personal information with third parties</li>
            <li>Username changes may take up to 24 hours to reflect across all features</li>
            <li>Email changes require verification (feature coming soon)</li>
            <li>Your data is protected by industry-standard security measures</li>
          </ul>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-3 pt-4">
          <Button onClick={handleSave} disabled={loading} className="min-w-32">
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Saving...
              </>
            ) : (
              <>
                <Save className="w-4 h-4 mr-2" />
                Save Changes
              </>
            )}
          </Button>
          <Button variant="outline" onClick={onBack} disabled={loading}>
            Cancel
          </Button>
        </div>
      </Card>

      {/* Avatar Selector Dialog */}
      <AvatarSelectorDialog
        open={showAvatarSelector}
        onClose={() => setShowAvatarSelector(false)}
        currentAvatar={selectedAvatar}
        onConfirm={async (animalId) => {
          setSelectedAvatar(animalId);
          toast.success('Avatar selected! Remember to save your changes.');
          return Promise.resolve();
        }}
      />
    </div>
  );
}
