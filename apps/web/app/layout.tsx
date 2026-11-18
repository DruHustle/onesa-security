import type {Metadata} from "next";
import "./globals.css";
export const metadata: Metadata = {
  title: {default: "Onesa Security | Control Plane", template: "%s | Onesa Security"},
  description: "Onesa Security — authorized security visibility, guardrails and investigations",
  robots: {index: false, follow: false},
};
export const dynamic = "force-dynamic";
export default function RootLayout({children}: {children: React.ReactNode}) {
  return <html lang="en"><body><a className="skip" href="#main-content">Skip to main content</a>{children}</body></html>;
}
