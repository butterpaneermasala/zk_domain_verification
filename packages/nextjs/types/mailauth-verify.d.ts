// Minimal type declaration to satisfy TS for dynamic import of mailauth verifier
declare module "mailauth/lib/dkim/verify" {
  // Keep types loose; refine later if needed
  export function dkimVerify(input: any): Promise<any>;
}
