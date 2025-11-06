import { AppProviders } from "../components/AppProviders";
import "~~/styles/globals.css";

export const metadata = {
  title: "Email Domain Verifier",
  description: "Headers-only DKIM + minimal ZK + optional on-chain badge",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html data-theme="light" suppressHydrationWarning>
      <body>
        <AppProviders>
          <div className="min-h-screen flex flex-col">
            <header className="sticky top-0 z-20 bg-base-100 border-b-4 border-base-content p-3">
              <div className="container mx-auto max-w-5xl flex items-center justify-between">
                <div className="font-extrabold text-xl tracking-tight uppercase">Email Domain Verifier</div>
                <div className="text-xs opacity-60">ZK login · no wallet</div>
              </div>
            </header>
            <main className="flex-1">{children}</main>
            <footer className="bg-base-100 border-t-4 border-base-content p-3">
              <div className="container mx-auto max-w-5xl text-xs">
                <span className="font-semibold">Privacy-first</span> · Headers-only DKIM · Minimal ZK · Optional mint
              </div>
            </footer>
          </div>
        </AppProviders>
      </body>
    </html>
  );
}
