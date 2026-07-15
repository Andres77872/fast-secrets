import { qrcodegen } from "./qrcodegen.js";

export function renderQr(container, text, label = "Enrollment QR code") {
  container.replaceChildren();
  if (!text) { container.hidden = true; return; }
  const qr = qrcodegen.QrCode.encodeText(String(text), qrcodegen.QrCode.Ecc.MEDIUM);
  const border = 4;
  const scale = Math.max(3, Math.floor(260 / (qr.size + border * 2)));
  const size = (qr.size + border * 2) * scale;
  const canvas = document.createElement("canvas");
  canvas.width = size; canvas.height = size; canvas.setAttribute("role", "img"); canvas.setAttribute("aria-label", label);
  const context = canvas.getContext("2d", { alpha: false });
  context.fillStyle = "#ffffff"; context.fillRect(0, 0, size, size); context.fillStyle = "#000000";
  for (let y = 0; y < qr.size; y++) {
    for (let x = 0; x < qr.size; x++) {
      if (qr.getModule(x, y)) context.fillRect((x + border) * scale, (y + border) * scale, scale, scale);
    }
  }
  const detail = document.createElement("div"); detail.className = "qr-detail";
  const title = document.createElement("strong"); title.textContent = label;
  const note = document.createElement("span"); note.textContent = "Rendered entirely in this browser. The enrollment URI was not uploaded or cached.";
  detail.append(title, note); container.append(canvas, detail); container.hidden = false;
}
