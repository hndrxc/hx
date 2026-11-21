// Fixture for Semgrep rule tests only; never built or executed.
declare const React: any;
declare const el: HTMLElement;
declare const untrusted: string;

export function Bad() {
  // ruleid: hx-js-active-html-sink
  return <div dangerouslySetInnerHTML={{ __html: untrusted }} />;
}

export function BadProps() {
  // ruleid: hx-js-active-html-sink
  return React.createElement("div", { dangerouslySetInnerHTML: { __html: untrusted } });
}

export function setters() {
  // ruleid: hx-js-active-html-sink
  el.innerHTML = untrusted;
  // ruleid: hx-js-active-html-sink
  el.outerHTML = untrusted;
  // ruleid: hx-js-active-html-sink
  el.insertAdjacentHTML("beforeend", untrusted);
  // ruleid: hx-js-active-html-sink
  document.write(untrusted);
}

export function Good() {
  // ok: hx-js-active-html-sink
  el.textContent = untrusted;
  // ok: hx-js-active-html-sink
  const current = el.innerHTML;
  // ok: hx-js-active-html-sink
  return <div>{untrusted}</div>;
}
