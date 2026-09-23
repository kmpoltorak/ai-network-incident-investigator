import { useState, type FormEvent } from "react";
import { api, type CreateIncident, type Incident } from "../api";

const PRESETS: Record<string, { label: string; incident: CreateIncident }> = {
  packet_loss: {
    label: "Packet loss",
    incident: {
      title: "Warehouse WAW-01 has intermittent connectivity",
      description: "Handheld scanners lose connection to the WMS every few minutes since 08:00.",
      target_host: "gw.waw01.example.net",
      target_port: 443,
    },
  },
  dns_failure: {
    label: "DNS",
    incident: {
      title: "Users cannot resolve internal application hostnames",
      description: "Since the resolver maintenance, users get 'server not found'. Access by IP works.",
      target_host: "app.corp.example.com",
      target_port: 443,
    },
  },
  tcp_failure: {
    label: "TCP",
    incident: {
      title: "Application cannot connect to the database service",
      description: "The order service logs 'connection refused' after the database host was patched.",
      target_host: "db.corp.example.com",
      target_port: 5432,
    },
  },
};

const empty = { title: "", description: "", target_host: "", target_port: "" };

export default function CreateIncidentForm({ onCreated }: { onCreated: (inc: Incident, scenario: string) => void }) {
  const [form, setForm] = useState(empty);
  const [preset, setPreset] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const set = (key: keyof typeof empty) => (e: { target: { value: string } }) => setForm({ ...form, [key]: e.target.value });

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const inc = await api.createIncident({
        title: form.title,
        description: form.description,
        target_host: form.target_host,
        ...(form.target_port ? { target_port: Number(form.target_port) } : {}),
      });
      setError("");
      setForm(empty);
      onCreated(inc, preset);
      setPreset("");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-semibold">New incident</h2>
        <div className="flex gap-1.5" role="group" aria-label="Sample incidents">
          {Object.entries(PRESETS).map(([key, p]) => (
            <button
              key={key}
              type="button"
              onClick={() => {
                const i = p.incident;
                setForm({ title: i.title, description: i.description, target_host: i.target_host, target_port: String(i.target_port ?? "") });
                setPreset(key);
              }}
              className="rounded-full border border-zinc-200 px-2.5 py-0.5 text-xs hover:border-indigo-500 dark:border-zinc-700"
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>
      <form onSubmit={submit} className="flex flex-col gap-3" noValidate>
        <label className="label">
          Title
          <input className="field" value={form.title} onChange={set("title")} maxLength={200} placeholder="Warehouse WAW-01 has intermittent connectivity" />
        </label>
        <label className="label">
          Description
          <textarea className="field resize-y" rows={3} value={form.description} onChange={set("description")} maxLength={5000} placeholder="What are users seeing?" />
        </label>
        <div className="flex gap-3">
          <label className="label flex-1">
            Target host
            <input className="field font-mono" value={form.target_host} onChange={set("target_host")} placeholder="gw.example.net" spellCheck={false} autoComplete="off" />
          </label>
          <label className="label w-24">
            Port
            <input className="field font-mono" type="number" min={1} max={65535} value={form.target_port} onChange={set("target_port")} placeholder="443" />
          </label>
        </div>
        {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
        <button type="submit" className="btn-primary" disabled={busy}>
          {busy ? "Creating…" : "Create incident"}
        </button>
      </form>
    </div>
  );
}
