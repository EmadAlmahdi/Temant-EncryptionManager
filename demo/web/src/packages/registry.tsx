import type { ComponentType } from "react";
import { ShieldCheck } from "lucide-react";
import { EncryptionManagerDemo } from "./encryption-manager/EncryptionManagerDemo";

export interface PackageDemo {
  id: string;
  name: string;
  tagline: string;
  icon: ComponentType<{ className?: string }>;
  component: ComponentType;
}

/**
 * Every Temant package demo registers itself here. Adding a future package to this app is just
 * a new entry — no changes to the shell (App.tsx / Sidebar.tsx) required.
 */
export const packages: PackageDemo[] = [
  {
    id: "encryption-manager",
    name: "Encryption Manager",
    tagline: "AES-GCM authenticated encryption",
    icon: ShieldCheck,
    component: EncryptionManagerDemo,
  },
];
