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
        this.innerHTML = '<ol class="chapter"><li class="chapter-item affix "><a href="getting_started.html">Introduction</a></li><li class="chapter-item affix "><li class="spacer"></li><li class="chapter-item affix "><li class="part-title">Tutorial</li><li class="chapter-item "><a href="tutorial/overview.html"><strong aria-hidden="true">1.</strong> Tutorial: Step-by-Step Guide</a><a class="toggle"><div>❱</div></a></li><li><ol class="section"><li class="chapter-item "><a href="tutorial/stage1_basic_promise.html"><strong aria-hidden="true">1.1.</strong> Stage 1: The Basic Promise</a></li><li class="chapter-item "><a href="tutorial/stage2_mixup_problem.html"><strong aria-hidden="true">1.2.</strong> Stage 2: The Mix-Up Problem</a></li><li class="chapter-item "><a href="tutorial/stage3_markers.html"><strong aria-hidden="true">1.3.</strong> Stage 3: Markers to the Rescue</a></li><li class="chapter-item "><a href="tutorial/stage4_authorization.html"><strong aria-hidden="true">1.4.</strong> Stage 4: Authorization with change_marker()</a></li><li class="chapter-item "><a href="tutorial/stage5_virtual_paths.html"><strong aria-hidden="true">1.5.</strong> Stage 5: Virtual Paths for User Sandboxing</a></li><li class="chapter-item "><a href="tutorial/stage6_features.html"><strong aria-hidden="true">1.6.</strong> Stage 6: Feature Integration</a></li></ol></li><li class="chapter-item "><li class="spacer"></li><li class="chapter-item affix "><li class="part-title">Core Concepts</li><li class="chapter-item "><a href="type_system_guarantees.html"><strong aria-hidden="true">2.</strong> Type-System Guarantees</a></li><li class="chapter-item "><a href="security_methodology.html"><strong aria-hidden="true">3.</strong> Security Methodology</a></li><li class="chapter-item affix "><li class="spacer"></li><li class="chapter-item affix "><li class="part-title">Real-World Examples</li><li class="chapter-item "><a href="examples/overview.html"><strong aria-hidden="true">4.</strong> Examples Overview</a><a class="toggle"><div>❱</div></a></li><li><ol class="section"><li class="chapter-item "><a href="examples/web_upload_service.html"><strong aria-hidden="true">4.1.</strong> Web File Upload Service</a></li><li class="chapter-item "><a href="examples/config_manager.html"><strong aria-hidden="true">4.2.</strong> Configuration File Manager</a></li><li class="chapter-item "><a href="examples/multi_user_storage.html"><strong aria-hidden="true">4.3.</strong> Multi-User Document Storage</a></li><li class="chapter-item "><a href="examples/archive_extraction.html"><strong aria-hidden="true">4.4.</strong> Archive Extraction</a></li><li class="chapter-item "><a href="examples/cli_tool.html"><strong aria-hidden="true">4.5.</strong> CLI Tool with Safe Paths</a></li><li class="chapter-item "><a href="examples/type_safe_contexts.html"><strong aria-hidden="true">4.6.</strong> Type-Safe Context Separation</a></li></ol></li><li class="chapter-item "><li class="spacer"></li><li class="chapter-item affix "><li class="part-title">Axum Web Service Tutorial</li><li class="chapter-item "><a href="axum_tutorial/overview.html"><strong aria-hidden="true">5.</strong> Tutorial Overview</a><a class="toggle"><div>❱</div></a></li><li><ol class="section"><li class="chapter-item "><a href="axum_tutorial/chapter1_setup.html"><strong aria-hidden="true">5.1.</strong> Chapter 1: Project Setup</a></li><li class="chapter-item "><a href="axum_tutorial/chapter2_static_assets.html"><strong aria-hidden="true">5.2.</strong> Chapter 2: Static Assets</a></li><li class="chapter-item "><a href="axum_tutorial/chapter3_user_storage.html"><strong aria-hidden="true">5.3.</strong> Chapter 3: Per-User Storage</a></li></ol></li><li class="chapter-item "><li class="spacer"></li><li class="chapter-item affix "><li class="part-title">Features &amp; Integration</li><li class="chapter-item "><a href="os_directories.html"><strong aria-hidden="true">6.</strong> OS Standard Directories</a></li><li class="chapter-item affix "><li class="spacer"></li><li class="chapter-item affix "><li class="part-title">Best Practices</li><li class="chapter-item "><a href="best_practices.html"><strong aria-hidden="true">7.</strong> Guidelines &amp; Patterns</a></li><li class="chapter-item "><a href="anti_patterns.html"><strong aria-hidden="true">8.</strong> Common Mistakes to Avoid</a></li><li class="chapter-item affix "><li class="spacer"></li><li class="chapter-item affix "><li class="part-title">API Design</li><li class="chapter-item "><a href="ergonomics/overview.html"><strong aria-hidden="true">9.</strong> Ergonomics</a><a class="toggle"><div>❱</div></a></li><li><ol class="section"><li class="chapter-item "><a href="ergonomics/builtin_io.html"><strong aria-hidden="true">9.1.</strong> Builtin I/O Operations</a></li><li class="chapter-item "><a href="ergonomics/generic_functions.html"><strong aria-hidden="true">9.2.</strong> Generic Functions &amp; Markers</a></li><li class="chapter-item "><a href="ergonomics/daily_patterns.html"><strong aria-hidden="true">9.3.</strong> Daily Usage Patterns</a></li><li class="chapter-item "><a href="ergonomics/interop_display.html"><strong aria-hidden="true">9.4.</strong> Interop vs Display</a></li><li class="chapter-item "><a href="ergonomics/signatures.html"><strong aria-hidden="true">9.5.</strong> Function Signatures</a></li><li class="chapter-item "><a href="ergonomics/escape_hatches.html"><strong aria-hidden="true">9.6.</strong> Escape Hatches</a></li><li class="chapter-item "><a href="ergonomics/equality_ordering.html"><strong aria-hidden="true">9.7.</strong> Equality &amp; Ordering</a></li><li class="chapter-item "><a href="ergonomics/naming.html"><strong aria-hidden="true">9.8.</strong> Naming Conventions</a></li><li class="chapter-item "><a href="ergonomics/choosing_canonicalized_vs_lexical_solution.html"><strong aria-hidden="true">9.9.</strong> Canonicalized vs Lexical</a></li></ol></li><li class="chapter-item "><a href="design_decisions.html"><strong aria-hidden="true">10.</strong> Design Decisions (Frustrated Rustacean&#39;s Guide)</a></li><li class="chapter-item affix "><li class="spacer"></li><li class="chapter-item affix "><li class="part-title">Internals</li><li class="chapter-item "><a href="internals.html"><strong aria-hidden="true">11.</strong> Design &amp; Implementation</a></li><li class="chapter-item "><a href="type_history_design.html"><strong aria-hidden="true">12.</strong> Type-History Pattern</a></li><li class="chapter-item "><a href="development_story.html"><strong aria-hidden="true">13.</strong> Development Journey</a></li></ol>';
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
