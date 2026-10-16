import "server-only";
import { getServerSession } from "next-auth";
import { NextResponse } from "next/server";
import { authOptions } from "@/lib/auth";

export interface CurrentUser {
  id: string;
  name: string;
  email: string;
  image: string | null;
  provider: string | null;
}

export async function currentUser(): Promise<CurrentUser | null> {
  const session = await getServerSession(authOptions);
  const u = session?.user;
  if (!u?.id) return null;
  return { id: u.id, name: u.name ?? "Analyst", email: u.email ?? "", image: u.image ?? null, provider: u.provider ?? null };
}

export const unauthorized = () =>
  NextResponse.json({ error: "unauthorized", message: "Sign in required." }, { status: 401 });

export const fail = (status: number, error: string, message: string) =>
  NextResponse.json({ error, message }, { status });
