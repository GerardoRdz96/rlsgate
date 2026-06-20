// service-role key hardcoded in client-bundled source -> exposed-secret (CRITICAL)
import { createClient } from '@supabase/supabase-js';
const admin = createClient(
  'https://abcdefgh.supabase.co',
  'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJyb2xlIjogInNlcnZpY2Vfcm9sZSIsICJpc3MiOiAic3VwYWJhc2UiLCAiaWF0IjogMTcwMDAwMDAwMH0.c2lnbmF0dXJlX3BsYWNlaG9sZGVy'
);
export default admin;
