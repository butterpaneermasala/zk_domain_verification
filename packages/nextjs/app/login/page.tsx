"use client";

import { useMemo, useState } from "react";
import { keccak256, stringToBytes } from "viem";
import { useAccount, useReadContract } from "wagmi";

const DOMAIN_BADGE_ABI_MIN = [
  {
    inputs: [
      { internalType: "address", name: "account", type: "address" },
      { internalType: "uint256", name: "id", type: "uint256" },
    ],
    name: "balanceOf",
    outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
    stateMutability: "view",
    type: "function",
  },
] as const;

const DEFAULT_CONTRACT = process.env.NEXT_PUBLIC_BADGE_CONTRACT as string | undefined;

export default function LoginPage() {
  const { address } = useAccount();
  const [domain, setDomain] = useState("");
  const [contract, setContract] = useState<string>(DEFAULT_CONTRACT || "");

  const domainHashHex = useMemo(() => {
    if (!domain) return null;
    return keccak256(stringToBytes(domain.toLowerCase()));
  }, [domain]);

  const {
    data: bal,
    isLoading,
    error,
  } = useReadContract({
    address: (contract || "0x0000000000000000000000000000000000000000") as `0x${string}`,
    abi: DOMAIN_BADGE_ABI_MIN,
    functionName: "balanceOf",
    args: address && domainHashHex ? [address, BigInt(domainHashHex)] : undefined,
    query: { enabled: !!address && !!domainHashHex && !!contract },
  });

  const hasBadge = (bal as bigint | undefined) && (bal as bigint) > 0n;

  return (
    <div className="container mx-auto max-w-3xl p-6 space-y-6">
      <h1 className="text-2xl font-semibold">Login with wallet</h1>
      <p className="text-sm text-neutral">We{"'"}ll check if your connected wallet owns the badge for your domain.</p>

      <section className="space-y-3">
        <label className="block text-sm font-medium">Domain</label>
        <input
          className="input input-bordered w-full"
          placeholder="example.com"
          value={domain}
          onChange={e => setDomain(e.target.value)}
        />
        <label className="block text-sm font-medium">Badge contract address</label>
        <input
          className="input input-bordered w-full"
          placeholder="0x..."
          value={contract}
          onChange={e => setContract(e.target.value)}
        />
        {address ? (
          <div className="mt-2">
            {isLoading ? (
              <div className="alert">Checking badge…</div>
            ) : error ? (
              <div className="alert alert-error">{String(error)}</div>
            ) : hasBadge ? (
              <div className="alert border-4 border-base-content">
                <div>
                  <h2 className="font-extrabold">Welcome back</h2>
                  <p className="text-sm">Your wallet holds the badge for {domain}.</p>
                </div>
              </div>
            ) : (
              <div className="alert">No badge found for {domain} on this wallet.</div>
            )}
          </div>
        ) : (
          <div className="alert">Connect wallet to check.</div>
        )}
      </section>

      <div className="text-sm">
        <p>
          Need to verify?{" "}
          <a className="link" href="/headers-verify-mint">
            Verify headers and mint
          </a>
        </p>
      </div>
    </div>
  );
}
