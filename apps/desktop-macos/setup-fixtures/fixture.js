// 无网络、无支付、无副作用；只有页面内计数用于证明阻断是否生效。
for (const id of ["ordinary", "payment"]) {
  document.getElementById(id).addEventListener("click", () => {
    const counter = document.getElementById(`${id}-count`);
    counter.value = String(Number(counter.value) + 1);
  });
}
