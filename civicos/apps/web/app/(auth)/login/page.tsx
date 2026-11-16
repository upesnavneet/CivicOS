import type { Metadata } from "next";
import Link from "next/link";
import { login } from "@/app/auth/actions";
import { Button, Card, ErrorNote, Field } from "@/components/ui";

export const metadata: Metadata = { title: "Sign in" };

export default async function LoginPage({ searchParams }: PageProps<"/login">) {
  const { error } = await searchParams;

  return (
    <Card className="p-6">
      <h1 className="text-xl font-semibold tracking-tight">Sign in</h1>
      <p className="mt-1 text-sm text-muted">Access your municipality&apos;s workspace.</p>

      <form action={login} className="mt-6 space-y-4">
        <ErrorNote message={typeof error === "string" ? error : undefined} />
        <Field label="Email" name="email" type="email" autoComplete="email" required />
        <Field label="Password" name="password" type="password" autoComplete="current-password" required />
        <Button type="submit" className="w-full">
          Sign in
        </Button>
      </form>

      <p className="mt-6 text-center text-sm text-muted">
        New municipality?{" "}
        <Link href="/register" className="text-accent hover:underline">
          Register an organization
        </Link>
      </p>
    </Card>
  );
}
