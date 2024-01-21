<!-- BEGIN: Sidebar -->
<div class="sidebar-wrapper group w-0 hidden xl:w-[248px] xl:block">
    <div id="bodyOverlay" class="w-screen h-screen fixed top-0 bg-slate-900 bg-opacity-50 backdrop-blur-sm z-10 hidden">
    </div>
    <div class="logo-segment">

        <!-- Application Logo -->
        <x-application-logo />

        <!-- Sidebar Type Button -->
        <div id="sidebar_type" class="cursor-pointer text-slate-900 dark:text-white text-lg">
            <iconify-icon class="sidebarDotIcon extend-icon text-slate-900 dark:text-slate-200" icon="fa-regular:dot-circle"></iconify-icon>
            <iconify-icon class="sidebarDotIcon collapsed-icon text-slate-900 dark:text-slate-200" icon="material-symbols:circle-outline"></iconify-icon>
        </div>
        <button class="sidebarCloseIcon text-2xl inline-block md:hidden">
            <iconify-icon class="text-slate-900 dark:text-slate-200" icon="clarity:window-close-line"></iconify-icon>
        </button>
    </div>
    <div id="nav_shadow" class="nav_shadow h-[60px] absolute top-[80px] nav-shadow z-[1] w-full transition-all duration-200 pointer-events-none
      opacity-0"></div>
    <div class="sidebar-menus bg-white dark:bg-slate-800 py-2 px-4 h-[calc(100%-80px)] z-50" id="sidebar_menus">
        <ul class="sidebar-menu">
            <li class="sidebar-menu-title">{{ __('MENU') }}</li>
            <li class="{{ (\Request::route()->getName() == 'dashboards*') ? 'active' : '' }}">
                <a href="#" class="navItem">
                    <span class="flex items-center">
                        <iconify-icon class=" nav-icon" icon="heroicons-outline:home"></iconify-icon>
                        <span>{{ __('Dashboard') }}</span>
                    </span>
                    <iconify-icon class="icon-arrow" icon="heroicons-outline:chevron-right"></iconify-icon>
                </a>
                <ul class="sidebar-submenu">
                    <li>
                        <a href="{{ route('dashboards.analytic') }}" class="navItem {{ (\Request::route()->getName() == 'dashboards.analytic') ? 'active' : '' }}">{{ __('Analytical Dashboard') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('dashboards.ecommerce') }}" class="navItem {{ (\Request::route()->getName() == 'dashboards.ecommerce') ? 'active' : '' }}">{{ __('Ecommerce Dashboard') }}
                        </a>
                    </li>
                </ul>
            </li>
            <!-- Apps Area -->
            <li class="sidebar-menu-title">{{ __('APPS') }}</li>
            <li>
                <a href="{{ route('chat') }}" class="navItem {{ (\Request::route()->getName() == 'chat') ? 'active' : '' }}">
                    <span class="flex items-center">
                        <iconify-icon class="nav-icon" icon="heroicons-outline:chat"></iconify-icon>
                        <span>{{ __('Chat') }}</span>
                    </span>
                </a>
            </li>
            <li class="">
                <a href="{{ route('email') }}" class="navItem {{ (\Request::route()->getName() == 'email') ? 'active' : '' }}">
                    <span class="flex items-center">
                        <iconify-icon class=" nav-icon" icon="heroicons-outline:mail"></iconify-icon>
                        <span>{{ __('Email') }}</span>
                    </span>
                </a>
            </li>
            <li>
                <a href="{{ route('kanban') }}" class="navItem {{ (\Request::route()->getName() == 'kanban') ? 'active' : '' }}">
                    <span class="flex items-center">
                        <iconify-icon class=" nav-icon" icon="heroicons-outline:view-boards"></iconify-icon>
                        <span>{{ __('Kanban') }}</span>
                    </span>
                </a>
            </li>
            <li>
                <a href="{{ route('calender') }}" class="navItem {{ (\Request::route()->getName() == 'calender') ? 'active' : '' }}">
                    <span class="flex items-center">
                        <iconify-icon class=" nav-icon" icon="heroicons-outline:calendar"></iconify-icon>
                        <span>{{ __('Calander') }}</span>
                    </span>
                </a>
            </li>
            <li>
                <a href="{{ route('todo') }}" class="navItem {{ (\Request::route()->getName() == 'todo') ? 'active' : '' }}">
                    <span class="flex items-center">
                        <iconify-icon class=" nav-icon" icon="heroicons-outline:clipboard-check"></iconify-icon>
                        <span>{{ __('Todo') }}</span>
                    </span>
                </a>
            </li>
            <li class="{{ (\Request::route()->getName() == 'project*') ? 'active' : '' }}">
                <a href="javascript:void(0)" class="navItem">
                    <span class="flex items-center">
                        <iconify-icon class=" nav-icon" icon="heroicons-outline:document"></iconify-icon>
                        <span>{{ __('Projects') }}</span>
                    </span>
                    <iconify-icon class="icon-arrow" icon="heroicons-outline:chevron-right"></iconify-icon>
                </a>
                <ul class="sidebar-submenu">
                    <li>
                        <a href="{{ route('project') }}" class="{{ (\Request::route()->getName() == 'project') ? 'active' : '' }}">{{ __('Projects') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('project-details') }}" class="{{ (\Request::route()->getName() == 'projectDetails') ? 'active' : '' }}">{{ __('Project Details') }}</a>
                    </li>
                </ul>
            </li>
            <!-- Pages Area -->
            <li class="sidebar-menu-title">{{ __('PAGES') }}</li>
            <!-- Utility -->
            <li class="{{ (\Request::route()->getName() == 'utility*') ? 'active' : '' }}">
                <a href="javascript:void(0)" class="navItem">
                    <span class="flex items-center">
                        <iconify-icon class=" nav-icon" icon="heroicons-outline:view-boards"></iconify-icon>
                        <span>{{ __('Utility') }}</span>
                    </span>
                    <iconify-icon class="icon-arrow" icon="heroicons-outline:chevron-right"></iconify-icon>
                </a>
                <ul class="sidebar-submenu">
                    <li>
                        <a href="{{ route('utility.invoice') }}" class="{{ (\Request::route()->getName() == 'utility.invoice') ? 'active' : '' }}">{{ __('Invoice') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('utility.pricing') }}" class="{{ (\Request::route()->getName() == 'utility.pricing') ? 'active' : '' }}">{{ __('Pricing') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('utility.blog') }}" class="{{ (\Request::route()->getName() == 'utility.blog') ? 'active' : '' }}">{{ __('Blog') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('utility.blank') }}" class="{{ (\Request::route()->getName() == 'utility.blank') ? 'active' : '' }}">{{ __('Blank Page') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('utility.profile') }}" class="{{ (\Request::route()->getName() == 'utility.profile') ? 'active' : '' }}">{{ __('Profile') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('utility.404') }}" class="{{ (\Request::route()->getName() == 'utility.404') ? 'active' : '' }}">{{ __('404 Pages') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('utility.coming-soon') }}" class="{{ (\Request::route()->getName() == 'utility.coming-soon') ? 'active' : '' }}">{{ __('Coming Soon') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('utility.under-maintenance') }}" class="{{ (\Request::route()->getName() == 'utility-under-maintenance') ? 'active' : '' }}">{{ __('Under Maintenance') }}</a>
                    </li>
                </ul>
            </li>
            <!-- Elements Area -->
            <li class="sidebar-menu-title">{{ __('ELEMENTS') }}</li>
            <!-- Widgets -->
            <li class="{{ (\Request::route()->getName() == 'widget*') ? 'active' : '' }}">
                <a href="javascript:void(0)" class="navItem">
                    <span class="flex items-center">
                        <iconify-icon class=" nav-icon" icon="heroicons-outline:view-grid-add"></iconify-icon>
                        <span>{{ __('Widgets') }}</span>
                    </span>
                    <iconify-icon class="icon-arrow" icon="heroicons-outline:chevron-right"></iconify-icon>
                </a>
                <ul class="sidebar-submenu">
                    <li>
                        <a href="{{ route('widget.basic') }}" class="{{ (\Request::route()->getName() == 'widget.basic') ? 'active' : '' }}">{{ __('Basic') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('widget.statistic') }}" class="{{ (\Request::route()->getName() == 'widget.statistic') ? 'active' : '' }}">{{ __('Statistics') }}</a>
                    </li>
                </ul>
            </li>
            <!-- Components -->
            <li class="{{ (\Request::route()->getName() == 'components*') ? 'active' : '' }}">
                <a href="javascript:void(0)" class="navItem">
                    <span class="flex items-center">
                        <iconify-icon class=" nav-icon" icon="heroicons-outline:collection"></iconify-icon>
                        <span>{{ __('Components') }}</span>
                    </span>
                    <iconify-icon class="icon-arrow" icon="heroicons-outline:chevron-right"></iconify-icon>
                </a>
                <ul class="sidebar-submenu">
                    <li>
                        <a href="{{ route('components.typography') }}" class="{{ (\Request::route()->getName() == 'components.typography') ? 'active' : '' }}">{{ __('Typography') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('components.colors') }}" class="{{ (\Request::route()->getName() == 'components.colors') ? 'active' : '' }}">{{ __('Colors') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('components.alert') }}" class="{{ (\Request::route()->getName() == 'components.alert') ? 'active' : '' }}">{{ __('Alert') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('components.button') }}" class="{{ (\Request::route()->getName() == 'components.button') ? 'active' : '' }}">{{ __('Button') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('components.card') }}" class="{{ (\Request::route()->getName() == 'components.card') ? 'active' : '' }}">{{ __('Card') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('components.carousel') }}" class="{{ (\Request::route()->getName() == 'components.carousel') ? 'active' : '' }}">{{ __('Carousel') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('components.dropdown') }}" class="{{ (\Request::route()->getName() == 'components.dropdown') ? 'active' : '' }}">{{ __('Dropdown') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('components.image') }}" class="{{ (\Request::route()->getName() == 'components.image') ? 'active' : '' }}">{{ __('Image') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('components.modal') }}" class="{{ (\Request::route()->getName() == 'components.modal') ? 'active' : '' }}">{{ __('Modal') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('components.progress-bar') }}" class="{{ (\Request::route()->getName() == 'components.progress-bar') ? 'active' : '' }}">{{ __('Progress bar') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('components.placeholder') }}" class="{{ (\Request::route()->getName() == 'components.placeholder') ? 'active' : '' }}">{{ __('Placeholder') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('components.tab') }}" class="{{ (\Request::route()->getName() == 'components.tab') ? 'active' : '' }}">{{ __('Tab & Accordion') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('components.badges') }}" class="{{ (\Request::route()->getName() == 'components.badges') ? 'active' : '' }}">{{ __('Badges') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('components.pagination') }}" class="{{ (\Request::route()->getName() == 'components.pagination') ? 'active' : '' }}">Pagination</a>
                    </li>
                    <li>
                        <a href="{{ route('components.video') }}" class="{{ (\Request::route()->getName() == 'components.video') ? 'active' : '' }}">{{ __('Video') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('components.tooltip') }}" class="{{ (\Request::route()->getName() == 'components.tooltip') ? 'active' : '' }}">{{ __('Tooltip & Popover') }}</a>
                    </li>
                </ul>
            </li>
            <!-- Forms -->
            <li class="{{ (\Request::route()->getName() == 'forms*') ? 'active' : '' }}">
                <a href="javascript:void(0)" class="navItem">
                    <span class="flex items-center">
                        <iconify-icon class=" nav-icon" icon="heroicons-outline:clipboard-list"></iconify-icon>
                        <span>{{ __('Forms') }}</span>
                    </span>
                    <iconify-icon class="icon-arrow" icon="heroicons-outline:chevron-right"></iconify-icon>
                </a>
                <ul class="sidebar-submenu">
                    <li>
                        <a href="{{ route('forms.input') }}" class="{{ (\Request::route()->getName() == 'forms.input') ? 'active' : '' }}">{{ __('Input') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('forms.input-group') }}" class="{{ (\Request::route()->getName() == 'forms.input-group') ? 'active' : '' }}">{{ __('Input group') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('forms.input-layout') }}" class="{{ (\Request::route()->getName() == 'forms.input-layout') ? 'active' : '' }}">{{ __('Input layout') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('forms.input-validation') }}" class="{{ (\Request::route()->getName() == 'forms.input-validation') ? 'active' : '' }}">{{ __('Form validation') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('forms.input-wizard') }}" class="{{ (\Request::route()->getName() == 'forms.input-wizard') ? 'active' : '' }}">{{ __('Wizard') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('forms.input-mask') }}" class="{{ (\Request::route()->getName() == 'forms.input-mask') ? 'active' : '' }}">{{ __('Input mask') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('forms.file-input') }}" class="{{ (\Request::route()->getName() == 'forms.file-input') ? 'active' : '' }}">{{ __('File input') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('forms.repeater') }}" class="{{ (\Request::route()->getName() == 'forms.repeater') ? 'active' : '' }}">{{ __('From repeater') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('forms.textarea') }}" class="{{ (\Request::route()->getName() == 'forms.textarea') ? 'active' : '' }}">{{ __('Textarea') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('forms.checkbox') }}" class="{{ (\Request::route()->getName() == 'forms.checkbox') ? 'active' : '' }}">{{ __('Checkbox') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('forms.radio') }}" class="{{ (\Request::route()->getName() == 'forms.radio') ? 'active' : '' }}">{{ __('Radio button') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('forms.switch') }}" class="{{ (\Request::route()->getName() == 'forms.switch') ? 'active' : '' }}">{{ __('Switch') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('forms.select') }}" class="{{ (\Request::route()->getName() == 'forms.select') ? 'active' : '' }}">{{ __('Select') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('forms.date-time-picker') }}" class="{{ (\Request::route()->getName() == 'forms.date-time-picker') ? 'active' : '' }}">{{ __('Date time picker') }}</a>
                    </li>
                </ul>
            </li>
            <!-- Tables -->
            <li class="{{ (\Request::route()->getName() == 'table*') ? 'active' : '' }}">
                <a href="javascript:void(0)" class="navItem">
                    <span class="flex items-center">
                        <iconify-icon class=" nav-icon" icon="heroicons-outline:table"></iconify-icon>
                        <span>{{ __('Tables') }}</span>
                    </span>
                    <iconify-icon class="icon-arrow" icon="heroicons-outline:chevron-right"></iconify-icon>
                </a>
                <ul class="sidebar-submenu">
                    <li>
                        <a href="{{ route('table.basic') }}" class="{{ (\Request::route()->getName() == 'table.basic') ? 'active' : '' }}">{{ __('Basic Tables') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('table.advance') }}" class="{{ (\Request::route()->getName() == 'table.advance') ? 'active' : '' }}">{{ __('Advanced Table') }}</a>
                    </li>
                </ul>
            </li>
            <!-- Charts -->
            <li class="{{ (\Request::route()->getName() == 'chart*') ? 'active' : '' }}">
                <a href="javascript:void(0)" class="navItem">
                    <span class="flex items-center">
                        <iconify-icon class=" nav-icon" icon="heroicons-outline:chart-bar"></iconify-icon>
                        <span>{{ __('Chart') }}</span>
                    </span>
                    <iconify-icon class="icon-arrow" icon="heroicons-outline:chevron-right"></iconify-icon>
                </a>
                <ul class="sidebar-submenu">
                    <li>
                        <a href="{{ route('chart.apex') }}" class="{{ (\Request::route()->getName() == 'chart.apex') ? 'active' : '' }}">{{ __('Apex Chart') }}</a>
                    </li>
                    <li>
                        <a href="{{ route('chart.index') }}" class="{{ (\Request::route()->getName() == 'chart.index') ? 'active' : '' }}">{{ __('Chart js') }}</a>
                    </li>
                </ul>
            </li>
            <!-- Map -->
            <li>
                <a href="{{ route('map') }}" class="navItem {{ (\Request::route()->getName() == 'map') ? 'active' : '' }}">
                    <span class="flex items-center">
                        <iconify-icon class=" nav-icon" icon="heroicons-outline:map"></iconify-icon>
                        <span>{{ __('Map') }}</span>
                    </span>
                </a>
            </li>
            <!-- Icons -->
            <li>
                <a href="{{ route('icon') }}" class="navItem {{ (\Request::route()->getName() == 'icon') ? 'active' : '' }}">
                    <span class="flex items-center">
                        <iconify-icon class=" nav-icon" icon="heroicons-outline:emoji-happy"></iconify-icon>
                        <span>{{ __('Icons') }}</span>
                    </span>
                </a>
            </li>
            <!-- Database -->
            <li>
                <a href="{{ route('database-backups.index') }}"
                   class="navItem {{ (request()->is('database-backups*')) ? 'active' : '' }}">
                    <span class="flex items-center">
                        <iconify-icon class=" nav-icon" icon="iconoir:database-backup"></iconify-icon>
                        <span>{{ __('Database Backup') }}</span>
                    </span>
                </a>
            </li>
            <!-- Settings -->
            <li>
                <a href="{{ route('general-settings.show') }}"
                   class="navItem {{ (request()->is('general-settings*')) || (request()->is('users*')) || (request()->is('roles*')) || (request()->is('profiles*')) || (request()->is('permissions*')) ? 'active' : '' }}">
                    <span class="flex items-center">
                        <iconify-icon class=" nav-icon" icon="material-symbols:settings-outline"></iconify-icon>
                        <span>{{ __('Settings') }}</span>
                    </span>
                </a>
            </li>
        </ul>
        <!-- Upgrade Your Business Plan Card Start -->
        <div class="bg-slate-900 mb-10 mt-24 p-4 relative text-center rounded-2xl text-white" id="sidebar_bottom_wizard">
            <img src="/images/svg/rabit.svg" alt="" class="mx-auto relative -mt-[73px]">
            <div class="max-w-[160px] mx-auto mt-6">
                <div class="widget-title font-Inter mb-1">Unlimited Access</div>
                <div class="text-xs font-light font-Inter">
                    Upgrade your system to business plan
                </div>
            </div>
            <div class="mt-6">
                <button class="bg-white hover:bg-opacity-80 text-slate-900 text-sm font-Inter rounded-md w-full block py-2 font-medium">
                    Upgrade
                </button>
            </div>
        </div>
        <!-- Upgrade Your Business Plan Card Start -->
    </div>
</div>
<!-- End: Sidebar -->
