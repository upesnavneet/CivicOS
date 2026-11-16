import type { Metadata } from "next";
import Link from "next/link";
import { registerOrganization } from "@/app/auth/actions";
import { Button, Card, ErrorNote, Field } from "@/components/ui";

export const metadata: Metadata = { title: "Register" };

export default async function RegisterPage({ searchParams }: PageProps<"/register">) {
  const { error } = await searchParams;

  return (
    <Card className="p-6">
      <h1 className="text-xl font-semibold tracking-tight">Register a municipality</h1>
      <p className="mt-1 text-sm text-muted">Creates an isolated workspace on the Free plan. You become its City Administrator.</p>

      <form action={registerOrganization} className="mt-6 space-y-4">
        <ErrorNote message={typeof error === "string" ? error : undefined} />
        <Field label="Organization name" name="org_name" placeholder="Brihanmumbai Municipal Corporation" required />
        <label className="block">
          <span className="mb-1.5 block text-sm font-medium text-ink">City dataset</span>
          <select name="city" defaultValue="mumbai" className="w-full rounded-lg border border-line bg-raised px-3 py-2.5 text-sm text-ink focus:border-accent focus:outline-none">
            <option value="mumbai">Mumbai: published BMC figures, 2016 to 2025</option>
            <option value="">None: start with an empty workspace</option>
          </select>
          <span className="mt-1 block text-xs text-muted">CivicOS loads only published data. It never generates sample data.</span>
        </label>
        <Field label="Your name" name="full_name" autoComplete="name" required />
        <Field label="Work email" name="email" type="email" autoComplete="email" required />
        <Field label="Password" name="password" type="password" autoComplete="new-password" minLength={8} hint="At least 8 characters." required />
        <Button type="submit" className="w-full">
          Create workspace
        </Button>
      </form>

      <p className="mt-6 text-center text-sm text-muted">
        Already registered?{" "}
        <Link href="/login" className="text-accent hover:underline">
          Sign in
        </Link>
      </p>
    </Card>
  );
}
