const MAX_TEXT = 200000;
const MAX_LINES = 1200;

function normalize(value, options) {
  let out = value;
  if (options.ignore_whitespace) out = out.replace(/\s+/g, " ").trim();
  if (options.ignore_case) out = out.toLocaleLowerCase();
  return out;
}

function lineDiff(left, right, options) {
  const a = left.split("\n");
  const b = right.split("\n");
  if (a.length > MAX_LINES || b.length > MAX_LINES) throw new Error(`Diff is limited to ${MAX_LINES.toLocaleString()} lines per pane`);
  const normalizedA = a.map(value => normalize(value, options));
  const normalizedB = b.map(value => normalize(value, options));
  const cols = b.length + 1;
  const table = new Uint16Array((a.length + 1) * cols);
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) {
      const idx = i * cols + j;
      table[idx] = normalizedA[i] === normalizedB[j]
        ? table[(i + 1) * cols + j + 1] + 1
        : Math.max(table[(i + 1) * cols + j], table[i * cols + j + 1]);
    }
  }
  const raw = []; let i = 0, j = 0;
  while (i < a.length || j < b.length) {
    if (i < a.length && j < b.length && normalizedA[i] === normalizedB[j]) {
      raw.push({ type: "equal", left: { num: i + 1, text: a[i] }, right: { num: j + 1, text: b[j] } }); i++; j++;
    } else if (j < b.length && (i === a.length || table[i * cols + j + 1] >= table[(i + 1) * cols + j])) {
      raw.push({ type: "add", left: null, right: { num: j + 1, text: b[j] } }); j++;
    } else {
      raw.push({ type: "remove", left: { num: i + 1, text: a[i] }, right: null }); i++;
    }
  }
  const rows = [];
  for (let k = 0; k < raw.length; k++) {
    const next = raw[k + 1];
    if (next && ((raw[k].type === "remove" && next.type === "add") || (raw[k].type === "add" && next.type === "remove"))) {
      const leftSide = raw[k].type === "remove" ? raw[k].left : next.left;
      const rightSide = raw[k].type === "add" ? raw[k].right : next.right;
      const [leftSegs, rightSegs] = highlight(leftSide.text, rightSide.text, options.granularity);
      rows.push({ type: "change", left: { ...leftSide, segs: leftSegs }, right: { ...rightSide, segs: rightSegs } }); k++;
    } else {
      const row = raw[k];
      if (row.left) row.left.segs = [{ text: row.left.text, hl: false }];
      if (row.right) row.right.segs = [{ text: row.right.text, hl: false }];
      rows.push(row);
    }
  }
  return rows;
}

function highlight(left, right, granularity) {
  const tokenize = granularity === "char" ? value => [...value] : value => value.split(/(\s+)/);
  const a = tokenize(left), b = tokenize(right);
  let prefix = 0;
  while (prefix < a.length && prefix < b.length && a[prefix] === b[prefix]) prefix++;
  let suffix = 0;
  while (suffix < a.length - prefix && suffix < b.length - prefix && a[a.length - 1 - suffix] === b[b.length - 1 - suffix]) suffix++;
  const segments = values => {
    const out = [];
    if (prefix) out.push({ text: values.slice(0, prefix).join(""), hl: false });
    if (values.length - prefix - suffix > 0) out.push({ text: values.slice(prefix, values.length - suffix).join(""), hl: true });
    if (suffix) out.push({ text: values.slice(values.length - suffix).join(""), hl: false });
    return out.length ? out : [{ text: "", hl: false }];
  };
  return [segments(a), segments(b)];
}

function unified(rows) {
  const lines = ["--- original", "+++ changed"];
  for (const row of rows) {
    if (row.type === "equal") lines.push(` ${row.left.text}`);
    else if (row.type === "remove") lines.push(`-${row.left.text}`);
    else if (row.type === "add") lines.push(`+${row.right.text}`);
    else { lines.push(`-${row.left.text}`); lines.push(`+${row.right.text}`); }
  }
  return lines.join("\n") + "\n";
}

export function compareText(text1, text2, options = {}) {
  if (text1.length > MAX_TEXT || text2.length > MAX_TEXT) throw new Error("Diff input is limited to 200,000 characters per pane");
  const rows = lineDiff(text1, text2, options);
  const stats = {
    added: rows.filter(row => row.type === "add").length,
    removed: rows.filter(row => row.type === "remove").length,
    changed: rows.filter(row => row.type === "change").length,
    unchanged: rows.filter(row => row.type === "equal").length,
  };
  stats.identical = stats.added === 0 && stats.removed === 0 && stats.changed === 0;
  const normalizedLeft = text1.split("\n").map(value => normalize(value, options)).join("\n");
  const normalizedRight = text2.split("\n").map(value => normalize(value, options)).join("\n");
  let common = 0;
  for (const row of rows) {
    if (row.type === "equal") { common += normalize(row.left.text, options).length; continue; }
    if (row.type !== "change") continue;
    const left = [...normalize(row.left.text, options)];
    const right = [...normalize(row.right.text, options)];
    let prefix = 0;
    while (prefix < left.length && prefix < right.length && left[prefix] === right[prefix]) prefix++;
    let suffix = 0;
    while (suffix < left.length - prefix && suffix < right.length - prefix && left[left.length - 1 - suffix] === right[right.length - 1 - suffix]) suffix++;
    common += prefix + suffix;
  }
  const combined = normalizedLeft.length + normalizedRight.length;
  stats.similarity = stats.identical ? 100 : combined ? Math.round(200 * common / combined) : 100;
  return { rows, stats, unified: unified(rows), options };
}
