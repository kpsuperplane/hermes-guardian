import { React } from "@/sdk";
import { text } from "@/lib/format";
import type { RiskBanner } from "@/types";

export interface RiskBannersProps {
  banners: RiskBanner[];
}

export function RiskBanners({ banners }: RiskBannersProps) {
  if (!banners.length) return null;
  return (
    <div className="hermes-guardian-risk-banners">
      {banners.map((banner) => (
        <div
          key={banner.id || banner.message}
          className="hermes-guardian-banner hermes-guardian-risk-banner"
        >
          <span className="hermes-guardian-risk-severity">
            {text(banner.severity || "risk")}
          </span>
          <span>{text(banner.message)}</span>
        </div>
      ))}
    </div>
  );
}
