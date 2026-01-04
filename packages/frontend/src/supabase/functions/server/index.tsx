import { Hono } from "npm:hono";
import { cors } from "npm:hono/cors";
import { logger } from "npm:hono/logger";
import { createClient } from '@supabase/supabase-js';
import * as kv from "./kv_store.tsx";

const app = new Hono();

// Enable logger
app.use('*', logger(console.log));

// Enable CORS for all routes and methods
app.use(
  "/*",
  cors({
    origin: "*",
    allowHeaders: ["Content-Type", "Authorization"],
    allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    exposeHeaders: ["Content-Length"],
    maxAge: 600,
  }),
);

// Initialize Supabase Admin Client
const supabase = createClient(
  Deno.env.get('SUPABASE_URL') ?? '',
  Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
);

// Health check endpoint
app.get("/make-server-a38e6980/health", (c) => {
  return c.json({ status: "ok" });
});

/**
 * Register a new user
 * POST /make-server-a38e6980/auth/register
 * Body: { email, password, name }
 */
app.post('/make-server-a38e6980/auth/register', async (c) => {
  console.log('Registration endpoint hit');
  
  try {
    const body = await c.req.json();
    console.log('Request body:', { email: body.email, name: body.name, username: body.username, avatar: body.avatar });
    const { email, password, name, username, avatar } = body;

    // Validate input
    if (!email || !password || !name || !username) {
      console.log('Validation failed: missing fields');
      return c.json({ 
        success: false, 
        error: 'All fields are required' 
      }, 400);
    }

    // Validate username format
    const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
    if (!usernameRegex.test(username)) {
      return c.json({ 
        success: false, 
        error: 'Username must be 3-20 characters and contain only letters, numbers, and underscores' 
      }, 400);
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return c.json({ 
        success: false, 
        error: 'Please enter a valid email address' 
      }, 400);
    }

    // Validate password strength
    if (password.length < 8) {
      return c.json({ 
        success: false, 
        error: 'Password must be at least 8 characters long' 
      }, 400);
    }

    const specialCharRegex = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/;
    if (!specialCharRegex.test(password)) {
      return c.json({ 
        success: false, 
        error: 'Password must contain at least one special character (!@#$%^&*...)' 
      }, 400);
    }

    // Check if username already exists by checking display_name
    console.log('Checking for existing username...');
    const { data: existingUsers } = await supabase.auth.admin.listUsers();
    const usernameExists = existingUsers.users?.some(
      user => user.user_metadata?.display_name?.toLowerCase() === username.toLowerCase()
    );
    
    if (usernameExists) {
      return c.json({ 
        success: false, 
        error: 'Username is already taken' 
      }, 400);
    }

    // Create user with Supabase Admin API
    console.log('Creating user in Supabase...');
    const { data, error } = await supabase.auth.admin.createUser({
      email: email.toLowerCase(),
      password: password,
      user_metadata: { 
        name: name,  // Full name stored in user_metadata
        display_name: username.toLowerCase(),  // Username stored in display_name
        avatar: avatar || 'lion'  // Animal ID (default to lion)
      },
      // Automatically confirm the user's email since email server hasn't been configured
      email_confirm: true
    });

    if (error) {
      console.log('Supabase registration error:', error);
      
      // Handle duplicate user error
      if (error.message.includes('already registered') || error.message.includes('User already registered')) {
        return c.json({ 
          success: false, 
          error: 'An account with this email already exists' 
        }, 400);
      }
      
      return c.json({ 
        success: false, 
        error: error.message 
      }, 400);
    }

    console.log('User created successfully:', data.user?.email);
    
    return c.json({ 
      success: true, 
      user: {
        id: data.user?.id,
        email: data.user?.email,
        name: data.user?.user_metadata?.name,
        username: data.user?.user_metadata?.display_name
      }
    });

  } catch (error) {
    console.log('Registration exception:', error);
    return c.json({ 
      success: false, 
      error: `Server error: ${error.message || 'Registration failed'}` 
    }, 500);
  }
});

// Update profile route
app.post('/make-server-a38e6980/auth/update-profile', async (c) => {
  try {
    const body = await c.req.json();
    const { userId, fullName, username, email, role, bio, avatar, currentPassword, newPassword } = body;

    console.log('Update profile request received for user:', userId);

    // Validate required fields
    if (!userId) {
      return c.json({ 
        success: false, 
        error: 'User ID is required' 
      }, 400);
    }

    if (!fullName || !username || !email) {
      return c.json({ 
        success: false, 
        error: 'Full name, username, and email are required' 
      }, 400);
    }

    const supabase = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '',
    );

    // Check if username is taken by another user
    const { data: existingUsers } = await supabase.auth.admin.listUsers();
    const usernameExists = existingUsers.users?.some(
      user => user.id !== userId && user.user_metadata?.display_name?.toLowerCase() === username.toLowerCase()
    );
    
    if (usernameExists) {
      return c.json({ 
        success: false, 
        error: 'Username is already taken by another user' 
      }, 400);
    }

    // Check if email is taken by another user
    const emailExists = existingUsers.users?.some(
      user => user.id !== userId && user.email?.toLowerCase() === email.toLowerCase()
    );
    
    if (emailExists) {
      return c.json({ 
        success: false, 
        error: 'Email is already in use by another account' 
      }, 400);
    }

    // If password change is requested, verify current password first
    if (newPassword) {
      console.log('Password change requested, verifying current password...');
      
      // Get the user's email to verify password
      const { data: userData } = await supabase.auth.admin.getUserById(userId);
      
      if (!userData.user) {
        return c.json({ 
          success: false, 
          error: 'User not found' 
        }, 404);
      }

      // Verify current password by trying to sign in
      const { error: signInError } = await supabase.auth.signInWithPassword({
        email: userData.user.email!,
        password: currentPassword,
      });

      if (signInError) {
        return c.json({ 
          success: false, 
          error: 'Current password is incorrect' 
        }, 400);
      }

      // Update password
      const { error: passwordError } = await supabase.auth.admin.updateUserById(
        userId,
        { password: newPassword }
      );

      if (passwordError) {
        console.log('Password update error:', passwordError);
        return c.json({ 
          success: false, 
          error: 'Failed to update password' 
        }, 400);
      }

      console.log('Password updated successfully');
    }

    // Update user metadata (profile information)
    const { data, error } = await supabase.auth.admin.updateUserById(
      userId,
      {
        email: email.toLowerCase(),
        user_metadata: {
          name: fullName,
          display_name: username.toLowerCase(),
          avatar: avatar || 'lion',  // Animal ID
          role: role || '',
          bio: bio || ''
        }
      }
    );

    if (error) {
      console.log('Profile update error:', error);
      return c.json({ 
        success: false, 
        error: error.message || 'Failed to update profile' 
      }, 400);
    }

    console.log('Profile updated successfully');
    
    return c.json({ 
      success: true,
      user: {
        id: data.user.id,
        email: data.user.email,
        name: data.user.user_metadata?.name,
        username: data.user.user_metadata?.display_name,
        role: data.user.user_metadata?.role,
        bio: data.user.user_metadata?.bio
      }
    });

  } catch (error) {
    console.log('Update profile exception:', error);
    return c.json({ 
      success: false, 
      error: `Server error: ${error.message || 'Update failed'}` 
    }, 500);
  }
});

Deno.serve(app.fetch);