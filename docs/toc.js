// Populate the sidebar
//
// This is a script, and not included directly in the page, to control the total size of the book.
// The TOC contains an entry for each page, so if each page includes a copy of the TOC,
// the total size of the page becomes O(n**2).
class MDBookSidebarScrollbox extends HTMLElement {
    constructor() {
        super();
    }
    connectedCallback() {
        this.innerHTML = '<ol class="chapter"><li class="chapter-item expanded "><a href="getting_started.html"><strong aria-hidden="true">1.</strong> Getting Started</a></li><li class="chapter-item expanded "><a href="development_story.html"><strong aria-hidden="true">2.</strong> The Journey to strict-path</a></li><li class="chapter-item expanded "><a href="examples.html"><strong aria-hidden="true">3.</strong> Real-World Examples</a></li><li class="chapter-item expanded "><a href="features.html"><strong aria-hidden="true">4.</strong> Features</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="os_directories.html"><strong aria-hidden="true">4.1.</strong> OS Standard Directories</a></li></ol></li><li class="chapter-item expanded "><a href="archive_extractors.html"><strong aria-hidden="true">5.</strong> Using with Archive Extractors</a></li><li class="chapter-item expanded "><a href="best_practices.html"><strong aria-hidden="true">6.</strong> Best Practices &amp; Guidelines</a></li><li class="chapter-item expanded "><a href="authorization_security.html"><strong aria-hidden="true">7.</strong> Path Permissions &amp; Authorization Security</a></li><li class="chapter-item expanded "><a href="ergonomics/overview.html"><strong aria-hidden="true">8.</strong> Ergonomics</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="ergonomics/interop_display.html"><strong aria-hidden="true">8.1.</strong> Interop vs Display</a></li><li class="chapter-item expanded "><a href="ergonomics/signatures.html"><strong aria-hidden="true">8.2.</strong> Function Signatures</a></li><li class="chapter-item expanded "><a href="ergonomics/escape_hatches.html"><strong aria-hidden="true">8.3.</strong> Escape Hatches</a></li><li class="chapter-item expanded "><a href="ergonomics/equality_ordering.html"><strong aria-hidden="true">8.4.</strong> Equality &amp; Ordering</a></li><li class="chapter-item expanded "><a href="ergonomics/naming.html"><strong aria-hidden="true">8.5.</strong> Naming</a></li><li class="chapter-item expanded "><a href="ergonomics/choosing_canonicalized_vs_lexical_solution.html"><strong aria-hidden="true">8.6.</strong> Choosing Canonicalized vs Lexical Solution</a></li></ol></li><li class="chapter-item expanded "><a href="internals.html"><strong aria-hidden="true">9.</strong> Design &amp; Internals</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="type_history_design.html"><strong aria-hidden="true">9.1.</strong> Type-History Design Pattern</a></li></ol></li><li class="chapter-item expanded "><a href="anti_patterns.html"><strong aria-hidden="true">10.</strong> Common Mistakes to Avoid</a></li></ol>';
        // Set the current, active page, and reveal it if it's hidden
        let current_page = document.location.href.toString().split("#")[0].split("?")[0];
        if (current_page.endsWith("/")) {
            current_page += "index.html";
        }
        var links = Array.prototype.slice.call(this.querySelectorAll("a"));
        var l = links.length;
        for (var i = 0; i < l; ++i) {
            var link = links[i];
            var href = link.getAttribute("href");
            if (href && !href.startsWith("#") && !/^(?:[a-z+]+:)?\/\//.test(href)) {
                link.href = path_to_root + href;
            }
            // The "index" page is supposed to alias the first chapter in the book.
            if (link.href === current_page || (i === 0 && path_to_root === "" && current_page.endsWith("/index.html"))) {
                link.classList.add("active");
                var parent = link.parentElement;
                if (parent && parent.classList.contains("chapter-item")) {
                    parent.classList.add("expanded");
                }
                while (parent) {
                    if (parent.tagName === "LI" && parent.previousElementSibling) {
                        if (parent.previousElementSibling.classList.contains("chapter-item")) {
                            parent.previousElementSibling.classList.add("expanded");
                        }
                    }
                    parent = parent.parentElement;
                }
            }
        }
        // Track and set sidebar scroll position
        this.addEventListener('click', function(e) {
            if (e.target.tagName === 'A') {
                sessionStorage.setItem('sidebar-scroll', this.scrollTop);
            }
        }, { passive: true });
        var sidebarScrollTop = sessionStorage.getItem('sidebar-scroll');
        sessionStorage.removeItem('sidebar-scroll');
        if (sidebarScrollTop) {
            // preserve sidebar scroll position when navigating via links within sidebar
            this.scrollTop = sidebarScrollTop;
        } else {
            // scroll sidebar to current active section when navigating via "next/previous chapter" buttons
            var activeSection = document.querySelector('#sidebar .active');
            if (activeSection) {
                activeSection.scrollIntoView({ block: 'center' });
            }
        }
        // Toggle buttons
        var sidebarAnchorToggles = document.querySelectorAll('#sidebar a.toggle');
        function toggleSection(ev) {
            ev.currentTarget.parentElement.classList.toggle('expanded');
        }
        Array.from(sidebarAnchorToggles).forEach(function (el) {
            el.addEventListener('click', toggleSection);
        });
    }
}
window.customElements.define("mdbook-sidebar-scrollbox", MDBookSidebarScrollbox);
