export default function SeverityBadge({ level }) {
  const lv = (level || "INFO").toUpperCase();
  return <span className={`badge badge-${lv}`}>{lv}</span>;
}
