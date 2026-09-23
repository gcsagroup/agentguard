/**
 * MAIN world 只包装未改写的 HTMLFormElement.prototype.submit。
 * 不读页面、不做判决、不发页面消息、没有放行入口。
 * 是否阻断由 isolated 内容脚本同步决定；页面若恢复 iframe 里的原生方法，仍不在保证内。
 */
(function () {
  "use strict";
  const proto = window.HTMLFormElement && HTMLFormElement.prototype;
  if (!proto) return;
  const descriptor = Object.getOwnPropertyDescriptor(proto, "submit");
  if (!descriptor || typeof descriptor.value !== "function") return;
  const nativeSubmit = descriptor.value;
  function wrappedSubmit() {
    const event = new CustomEvent("agentguard-native-submit", {
      bubbles: true,
      cancelable: true,
    });
    this.dispatchEvent(event);
    if (event.defaultPrevented) return;
    return nativeSubmit.apply(this, arguments);
  }
  try {
    Object.defineProperty(proto, "submit", {
      configurable: descriptor.configurable !== false,
      enumerable: !!descriptor.enumerable,
      writable: descriptor.writable !== false,
      value: wrappedSubmit,
    });
  } catch (_) {
    // 原型不可写时保持诚实限制，不强行改。
  }
})();
