import Link from "next/link";

export default function Forbidden() {
  return (
    <main className="mx-auto max-w-lg px-6 py-24">
      <h1 className="text-[24px] font-semibold">This page is not available for your role</h1>
      <p className="mt-2 text-[15px] text-muted">
        Developers see only their own projects. Analysts and admins see all vulnerabilities, and only
        admins see users and the audit log.
      </p>
      <Link href="/dashboard" className="mt-6 inline-block text-accent underline">Back to overview</Link>
    </main>
  );
}
