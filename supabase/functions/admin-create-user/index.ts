import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Content-Type": "application/json",
};

const usernamePattern = /^[a-zA-Z0-9._-]{3,32}$/;
const roles = new Set(["operator", "visitor", "validation"]);
const pages = new Set([
  "dashboard",
  "products",
  "stock",
  "machines",
  "team",
  "validation",
  "analytics",
]);

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: corsHeaders });
}

function validPageList(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || !pages.has(item))) {
    return null;
  }
  return [...new Set(value)];
}

export default {
  async fetch(req: Request): Promise<Response> {
    if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
    if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

    const url = Deno.env.get("SUPABASE_URL");
    const publishableKey = Deno.env.get("SUPABASE_ANON_KEY");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    const authorization = req.headers.get("authorization");
    if (!url || !publishableKey || !serviceRoleKey) {
      return json({ error: "Server configuration error" }, 500);
    }
    if (!authorization) return json({ error: "Authentication required" }, 401);

    const requesterClient = createClient(url, publishableKey, {
      global: { headers: { Authorization: authorization } },
    });
    const { data: authData, error: authError } = await requesterClient.auth.getUser();
    if (authError || !authData.user) return json({ error: "Authentication required" }, 401);

    const admin = createClient(url, serviceRoleKey);
    const { data: requester } = await admin
      .from("profiles")
      .select("role, status")
      .eq("id", authData.user.id)
      .maybeSingle();
    if (requester?.role !== "admin" || requester.status !== "active") {
      return json({ error: "Administrator permission required" }, 403);
    }

    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch (_) {
      return json({ error: "Invalid request" }, 400);
    }
    const username = typeof body.username === "string" ? body.username.trim().toLowerCase() : "";
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const fullName = typeof body.fullName === "string" ? body.fullName.trim() : "";
    const password = typeof body.password === "string" ? body.password : "";
    const role = typeof body.role === "string" ? body.role : "";
    const allowedPages = validPageList(body.allowedPages);
    const writablePages = validPageList(body.writablePages);

    if (!usernamePattern.test(username) || !/^\S+@\S+\.\S+$/.test(email) ||
      !fullName || fullName.length > 120 || !roles.has(role)) {
      return json({ error: "Invalid user details" }, 400);
    }
    if (password.length < 12 || password.length > 128 || !/[a-z]/.test(password) ||
      !/[A-Z]/.test(password) || !/[0-9]/.test(password) ||
      allowedPages === null || writablePages === null ||
      writablePages.some((page) => !allowedPages.includes(page))) {
      return json({ error: "Invalid access rights or password" }, 400);
    }

    const { data: created, error: createError } = await admin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { full_name: fullName, username },
    });
    if (createError || !created.user) {
      return json({ error: "Username is already used or account creation failed" }, 409);
    }

    const { data: profile, error: profileError } = await admin
      .from("profiles")
      .update({
        email,
        full_name: fullName,
        username,
        role,
        status: "active",
        allowed_pages: allowedPages,
        writable_pages: writablePages,
        updated_at: new Date().toISOString(),
      })
      .eq("id", created.user.id)
      .select()
      .single();
    if (profileError || !profile) {
      await admin.auth.admin.deleteUser(created.user.id);
      return json({ error: "Profile creation failed" }, 500);
    }
    return json({ profile });
  },
};
