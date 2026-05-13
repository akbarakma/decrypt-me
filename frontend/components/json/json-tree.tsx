"use client";

import { ChevronRight } from "lucide-react";
import { memo, useCallback, useMemo, useState } from "react";
import type { JsonValue } from "@/lib/json";

type JsonTreeProps = {
  value: JsonValue;
};

type JsonNodeProps = {
  label: string;
  value: JsonValue;
  path: string;
  depth: number;
  isCollapsed: boolean;
  collapsedPaths: ReadonlySet<string>;
  onToggle: (path: string) => void;
};

const ROOT_PATH = "$";

function childPath(parent: string, segment: string): string {
  return parent + "/" + JSON.stringify(segment);
}

export function JsonTree({ value }: JsonTreeProps) {
  const [collapsedPaths, setCollapsedPaths] = useState<ReadonlySet<string>>(() => new Set());

  const handleToggle = useCallback((path: string) => {
    setCollapsedPaths((current) => {
      const next = new Set(current);
      if (next.has(path)) {
        next.delete(path);
      } else {
        next.add(path);
      }
      return next;
    });
  }, []);

  return (
    <div className="max-h-[44rem] overflow-auto rounded-lg border border-white/10 bg-black/20 p-3 text-sm">
      <div className="min-w-max pr-4">
        <JsonNode
          collapsedPaths={collapsedPaths}
          depth={0}
          isCollapsed={collapsedPaths.has(ROOT_PATH)}
          label="root"
          onToggle={handleToggle}
          path={ROOT_PATH}
          value={value}
        />
      </div>
    </div>
  );
}

const JsonNode = memo(function JsonNode({
  label,
  value,
  path,
  depth,
  isCollapsed,
  collapsedPaths,
  onToggle
}: JsonNodeProps) {
  const isArray = Array.isArray(value);
  const isObject = isPlainObject(value);
  const canCollapse = isArray || isObject;
  const entries = useMemo(() => getEntries(value), [value]);
  const summary = useMemo(() => summarize(value), [value]);

  if (!canCollapse) {
    return (
      <div className="flex min-h-7 items-start gap-2 whitespace-pre" style={{ paddingLeft: depth * 16 }}>
        <span className="shrink-0 text-brass">{label}</span>
        <span className="text-white/35">:</span>
        <PrimitiveValue value={value} />
      </div>
    );
  }

  return (
    <div>
      <button
        className="flex min-h-7 w-full items-center gap-2 whitespace-pre rounded-md text-left text-white/85 transition hover:bg-white/5"
        onClick={() => onToggle(path)}
        style={{ paddingLeft: depth * 16 }}
        type="button"
      >
        <ChevronRight
          aria-hidden="true"
          className={`h-4 w-4 shrink-0 text-brass transition ${isCollapsed ? "" : "rotate-90"}`}
        />
        <span className="shrink-0 text-brass">{label}</span>
        <span className="text-white/35">:</span>
        <span className="text-white/65">{summary}</span>
      </button>
      {!isCollapsed && (
        <div>
          {entries.map(([entryLabel, entryValue]) => {
            const next = childPath(path, entryLabel);
            return (
              <JsonNode
                key={next}
                collapsedPaths={collapsedPaths}
                depth={depth + 1}
                isCollapsed={collapsedPaths.has(next)}
                label={entryLabel}
                onToggle={onToggle}
                path={next}
                value={entryValue}
              />
            );
          })}
        </div>
      )}
    </div>
  );
});

function PrimitiveValue({ value }: { value: JsonValue }) {
  if (typeof value === "string") {
    return <span className="text-emerald-200">{JSON.stringify(value)}</span>;
  }

  if (typeof value === "number") {
    return <span className="text-sky-200">{value}</span>;
  }

  if (typeof value === "boolean") {
    return <span className="text-amber-200">{String(value)}</span>;
  }

  return <span className="text-white/45">null</span>;
}

function getEntries(value: JsonValue): [string, JsonValue][] {
  if (Array.isArray(value)) {
    return value.map((item, index) => [String(index), item]);
  }

  if (isPlainObject(value)) {
    return Object.entries(value);
  }

  return [];
}

function summarize(value: JsonValue): string {
  if (Array.isArray(value)) {
    return `[${value.length} item${value.length === 1 ? "" : "s"}]`;
  }

  if (isPlainObject(value)) {
    const size = Object.keys(value).length;
    return `{${size} field${size === 1 ? "" : "s"}}`;
  }

  return "";
}

function isPlainObject(value: JsonValue): value is { [key: string]: JsonValue } {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
