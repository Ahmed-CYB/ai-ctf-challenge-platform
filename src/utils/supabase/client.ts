/**
 * Supabase Client
 * Singleton instance for frontend Supabase operations
 */

import { createClient } from '@supabase/supabase-js';
import { projectId, publicAnonKey } from './info';

let supabaseClient: ReturnType<typeof createClient> | null = null;

/**
 * Get or create Supabase client instance
 */
export function getSupabaseClient() {
  if (!supabaseClient) {
    const supabaseUrl = `https://${projectId}.supabase.co`;
    supabaseClient = createClient(supabaseUrl, publicAnonKey);
  }
  return supabaseClient;
}
