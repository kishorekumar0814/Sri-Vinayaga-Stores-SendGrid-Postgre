// foldable nav
const side = document.getElementById('sideNav');
const toggle = document.getElementById('navToggle');
if(toggle){
  toggle.addEventListener('click', () => {
    side.classList.toggle('collapsed');
  });
}

function cardPop(el){
  el.classList.add('pop');
  setTimeout(()=> el.classList.remove('pop'), 400);
}


document.addEventListener("DOMContentLoaded", () => {
    const toggleBtn = document.querySelector(".nav-toggle");
    const sidenav = document.querySelector(".sidenav");

    if (toggleBtn && sidenav) {
        toggleBtn.addEventListener("click", () => {
            sidenav.classList.toggle("open");
        });
    }
});
