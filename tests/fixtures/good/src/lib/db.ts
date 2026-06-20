import { createClient } from '@supabase/supabase-js';
// secret read from a SERVER-ONLY env var, never inlined to the client
export const admin = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);
