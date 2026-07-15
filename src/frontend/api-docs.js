"use strict";

const endpointRoot = document.querySelector("#endpoints");
const status = document.querySelector("#status");

const element = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
};

function responseMedia(operation) {
  const values = new Set();
  for (const response of Object.values(operation.responses || {})) {
    for (const mediaType of Object.keys(response.content || {})) values.add(mediaType);
  }
  return [...values].sort();
}

function render(specification) {
  endpointRoot.replaceChildren();
  let count = 0;
  for (const [path, pathItem] of Object.entries(specification.paths || {})) {
    for (const method of ["get", "post", "put", "patch", "delete"]) {
      const operation = pathItem[method];
      if (!operation) continue;
      count += 1;
      const card = element("article", "endpoint");
      const route = element("div", "route");
      route.append(element("span", `method ${method}`, method.toUpperCase()), element("code", "path", path));
      card.append(route, element("p", "summary", operation.summary || operation.description || "API operation"));
      const media = element("div", "response-media");
      for (const value of responseMedia(operation)) media.appendChild(element("span", "media", value));
      if (media.children.length) card.appendChild(media);
      endpointRoot.appendChild(card);
    }
  }
  status.textContent = `${count} operations · OpenAPI ${specification.openapi || ""}`;
}

fetch("/openapi.json", { cache: "no-store", headers: { Accept: "application/json" } })
  .then(response => {
    if (!response.ok) throw new Error(`OpenAPI returned ${response.status}`);
    return response.json();
  })
  .then(render)
  .catch(error => {
    status.textContent = "Could not load OpenAPI";
    endpointRoot.appendChild(element("p", "summary", error.message));
  });
