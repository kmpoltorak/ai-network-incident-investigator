import type { Incident } from "./api";

export const target = (inc: Incident) => (inc.target_port ? `${inc.target_host}:${inc.target_port}` : inc.target_host);

export function timeAgo(iso: string): string {
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(iso).toLocaleDateString();
}
