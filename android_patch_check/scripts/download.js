var myLinks = document.getElementsByTagName("a");
console.log(myLinks.length)
for (var i = 0; i < myLinks.length; i++) {
  download(myLinks[i].href, myLinks[i].text)
  console.log(i)
  await sleep(200);
}
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function download(dataurl, filename) {
  var a = document.createElement("a");
  a.href = dataurl;
  a.setAttribute("download", filename);
  a.click();
}