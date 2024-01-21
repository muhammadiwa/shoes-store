<x-app-layout>
    <div class="space-y-8">
        <div>
          <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="grid xl:grid-cols-2 grid-cols-1 gap-6">
            <!-- BEGIN: Basic Dropdown -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Basic Dropdowns</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="btn-group-example btn-group">
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center btn-primary items-center" type="button" id="primaryDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> primary
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class="dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none" style="">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center btn-secondary items-center" type="button" id="secondaryDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> secondary
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class="dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none" style="">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center btn-info items-center" type="button" id="infoDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> info
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class="dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none" style="">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center btn-success items-center" type="button" id="successDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> success
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class="dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none" style="">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center btn-warning items-center" type="button" id="warningDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> warning
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center btn-danger items-center" type="button" id="dangerDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> danger
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center btn-dark items-center" type="button" id="darkDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> dark
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center btn-light items-center" type="button" id="lightDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> light
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Basic Dropdown -->
            <!-- BEGIN: Outline Dropdown -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Outline Dropdowns</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="btn-group-example btn-group">
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center btn-outline-primary items-center" type="button" id="primaryOutlineDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> primary
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class="dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none" style="">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center btn-outline-secondary items-center" type="button" id="secondaryOutlineDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> secondary
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class="dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none" style="">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center btn-outline-info items-center" type="button" id="infoOutlineDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> info
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class="dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none" style="">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center btn-outline-success items-center" type="button" id="successOutlineDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> success
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class="dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none" style="">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center btn-outline-warning items-center" type="button" id="warningOutlineDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> warning
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center btn-outline-danger items-center" type="button" id="dangerOutlineDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> danger
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center btn-outline-dark items-center" type="button" id="darkOutlineDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> dark
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center btn-outline-light items-center" type="button" id="lightOutlineDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> light
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Outline Dropdown -->
            <!-- BEGIN: Flat Dropdown -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Flat Dropdowns</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="btn-group-example btn-group">
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center text-primary-500 items-center" type="button" id="primaryFlatDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> primary
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center text-secondary-500 items-center" type="button" id="secondaryFlatDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> secondary
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center text-info-500 items-center" type="button" id="infoFlatDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> info
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center text-success-500 items-center" type="button" id="successFlatDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> success
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center text-warning-500 items-center" type="button" id="warningFlatDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> warning
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center text-danger-500 items-center" type="button" id="dangerFlatDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> danger
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center text-dark-500 items-center" type="button" id="darkFlatDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> dark
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center text-light-500 items-center" type="button" id="lightFlatDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> light
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Flat Dropdown -->
            <!-- BEGIN: Split Dropdown -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Split Dropdowns</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="btn-group-example btn-group">
                            <div class="dropdown relative ">
                                <button class="btn inline-flex justify-center btn-primary items-center cursor-default relative !pr-14" type="button" id="primarysplitDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> primary <span class="cursor-pointer absolute ltr:border-l rtl:border-r border-slate-100 h-full ltr:right-0 rtl:left-0 px-2 flex
                                                    items-center justify-center leading-none">
                        <iconify-icon class="leading-none text-xl" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                      </span> </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative ">
                                <button class="btn inline-flex justify-center btn-secondary items-center cursor-default relative !pr-14" type="button" id="secondarysplitDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> secondary <span class="cursor-pointer absolute ltr:border-l rtl:border-r border-slate-100 h-full ltr:right-0 rtl:left-0 px-2 flex
                                                    items-center justify-center leading-none">
                        <iconify-icon class="leading-none text-xl" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                      </span> </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative ">
                                <button class="btn inline-flex justify-center btn-info items-center cursor-default relative !pr-14" type="button" id="infosplitDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> info <span class="cursor-pointer absolute ltr:border-l rtl:border-r border-slate-100 h-full ltr:right-0 rtl:left-0 px-2 flex
                                                    items-center justify-center leading-none">
                        <iconify-icon class="leading-none text-xl" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                      </span> </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative ">
                                <button class="btn inline-flex justify-center btn-success items-center cursor-default relative !pr-14" type="button" id="successsplitDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> success <span class="cursor-pointer absolute ltr:border-l rtl:border-r border-slate-100 h-full ltr:right-0 rtl:left-0 px-2 flex
                                                    items-center justify-center leading-none">
                        <iconify-icon class="leading-none text-xl" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                      </span> </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative ">
                                <button class="btn inline-flex justify-center btn-warning items-center cursor-default relative !pr-14" type="button" id="warningsplitDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> warning <span class="cursor-pointer absolute ltr:border-l rtl:border-r border-slate-100 h-full ltr:right-0 rtl:left-0 px-2 flex
                                                    items-center justify-center leading-none">
                        <iconify-icon class="leading-none text-xl" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                      </span> </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative ">
                                <button class="btn inline-flex justify-center btn-danger items-center cursor-default relative !pr-14" type="button" id="dangersplitDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> danger <span class="cursor-pointer absolute ltr:border-l rtl:border-r border-slate-100 h-full ltr:right-0 rtl:left-0 px-2 flex
                                                    items-center justify-center leading-none">
                        <iconify-icon class="leading-none text-xl" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                      </span> </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative ">
                                <button class="btn inline-flex justify-center btn-dark items-center cursor-default relative !pr-14" type="button" id="darksplitDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> dark <span class="cursor-pointer absolute ltr:border-l rtl:border-r border-slate-100 h-full ltr:right-0 rtl:left-0 px-2 flex
                                                    items-center justify-center leading-none">
                        <iconify-icon class="leading-none text-xl" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                      </span> </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative ">
                                <button class="btn inline-flex justify-center btn-light items-center cursor-default relative !pr-14" type="button" id="lightsplitDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> light <span class="cursor-pointer absolute ltr:border-l rtl:border-r border-slate-100 h-full ltr:right-0 rtl:left-0 px-2 flex
                                                    items-center justify-center leading-none">
                        <iconify-icon class="leading-none text-xl" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                      </span> </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Split Dropdown -->
            <!-- BEGIN: Split Outline Dropdown -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Split Outline Dropdowns</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="btn-group-example btn-group">
                            <div class="dropdown relative ">
                                <button class="btn inline-flex justify-center btn-outline-primary items-center cursor-default relative !pr-14" type="button" id="primarysplitOutlineDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> primary <span class="cursor-pointer absolute ltr:border-l rtl:border-r border-primary-500 h-full ltr:right-0 rtl:left-0 px-2 flex
                                                    items-center justify-center leading-none">
                        <iconify-icon class="leading-none text-xl" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                      </span> </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative ">
                                <button class="btn inline-flex justify-center btn-outline-secondary items-center cursor-default relative !pr-14" type="button" id="secondarysplitOutlineDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> secondary <span class="cursor-pointer absolute ltr:border-l rtl:border-r border-secondary-500 h-full ltr:right-0 rtl:left-0 px-2 flex
                                                    items-center justify-center leading-none">
                        <iconify-icon class="leading-none text-xl" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                      </span> </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative ">
                                <button class="btn inline-flex justify-center btn-outline-info items-center cursor-default relative !pr-14" type="button" id="infosplitOutlineDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> info <span class="cursor-pointer absolute ltr:border-l rtl:border-r border-info-500 h-full ltr:right-0 rtl:left-0 px-2 flex
                                                    items-center justify-center leading-none">
                        <iconify-icon class="leading-none text-xl" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                      </span> </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative ">
                                <button class="btn inline-flex justify-center btn-outline-success items-center cursor-default relative !pr-14" type="button" id="successsplitOutlineDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> success <span class="cursor-pointer absolute ltr:border-l rtl:border-r border-success-500 h-full ltr:right-0 rtl:left-0 px-2 flex
                                                    items-center justify-center leading-none">
                        <iconify-icon class="leading-none text-xl" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                      </span> </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative ">
                                <button class="btn inline-flex justify-center btn-outline-warning items-center cursor-default relative !pr-14" type="button" id="warningsplitOutlineDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> warning <span class="cursor-pointer absolute ltr:border-l rtl:border-r border-warning-500 h-full ltr:right-0 rtl:left-0 px-2 flex
                                                    items-center justify-center leading-none">
                        <iconify-icon class="leading-none text-xl" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                      </span> </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative ">
                                <button class="btn inline-flex justify-center btn-outline-danger items-center cursor-default relative !pr-14" type="button" id="dangersplitOutlineDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> danger <span class="cursor-pointer absolute ltr:border-l rtl:border-r border-danger-500 h-full ltr:right-0 rtl:left-0 px-2 flex
                                                    items-center justify-center leading-none">
                        <iconify-icon class="leading-none text-xl" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                      </span> </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative ">
                                <button class="btn inline-flex justify-center btn-outline-dark items-center cursor-default relative !pr-14" type="button" id="darksplitOutlineDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> dark <span class="cursor-pointer absolute ltr:border-l rtl:border-r border-dark-500 h-full ltr:right-0 rtl:left-0 px-2 flex
                                                    items-center justify-center leading-none">
                        <iconify-icon class="leading-none text-xl" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                      </span> </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative ">
                                <button class="btn inline-flex justify-center btn-outline-light items-center cursor-default relative !pr-14" type="button" id="lightsplitOutlineDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> light <span class="cursor-pointer absolute ltr:border-l rtl:border-r border-light-500 h-full ltr:right-0 rtl:left-0 px-2 flex
                                                    items-center justify-center leading-none">
                        <iconify-icon class="leading-none text-xl" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                      </span> </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Split Outline Dropdown -->
            <!-- BEGIN: Directions Dropdown -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Dropdown Directions</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="flex items-center flex-wrap gap-2">
                            <!-- Dropdown Top -->
                            <div class="dropdup relative">
                                <button class="btn inline-flex justify-center btn-primary items-center" type="button" id="dropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> Drop Top
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2 rotate-180" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                            z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <!-- Dropdown Right -->
                            <div class="dropend relative">
                                <button class="btn inline-flex justify-center btn-primary items-center" type="button" id="rightDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> Drop Right
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2 -rotate-90" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                            z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <!-- Dropdown Bottom -->
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center btn-primary items-center" type="button" id="bottomDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> Drop Down
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                            z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <!-- Dropdown Left -->
                            <div class="dropstart relative">
                                <button class="btn inline-flex justify-center btn-primary items-center" type="button" id="leftDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false">
                                    <iconify-icon class="text-xl ltr:ml-r rtl:ml-2 rotate-90" icon="ic:round-keyboard-arrow-down"></iconify-icon> Drop Left </button>
                                <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                            z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Directions Dropdown -->
            <!-- BEGIN: Dropdown Sizes -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Dropdown Sizes</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="btn-group-example btn-group">
                            <div class="relative">
                                <div class="dropdown relative">
                                    <button class="btn btn-xl inline-flex justify-center btn-primary items-center" type="button" id="largeDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> primary
                                        <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                    </button>
                                    <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                        <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                          Action</a> </li>
                                        <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                          Another Action</a> </li>
                                        <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                          Something else here</a> </li>
                                        <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                          Sign out</a> </li>
                                    </ul>
                                </div>
                            </div>
                            <div class="relative">
                                <div class="dropdown relative">
                                    <button class="btn inline-flex justify-center btn-primary items-center" type="button" id="defaultsDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> primary
                                        <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                    </button>
                                    <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                        <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                          Action</a> </li>
                                        <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                          Another Action</a> </li>
                                        <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                          Something else here</a> </li>
                                        <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                          Sign out</a> </li>
                                    </ul>
                                </div>
                            </div>
                            <div class="relative">
                                <div class="dropdown relative">
                                    <button class="btn inline-flex justify-center btn-primary items-center btn-sm" type="button" id="smallDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false"> primary
                                        <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                    </button>
                                    <ul class=" dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                                z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                        <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                          Action</a> </li>
                                        <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                          Another Action</a> </li>
                                        <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white">
                                          Something else here</a> </li>
                                        <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                        dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                          Sign out</a> </li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Sizes Dropdown -->
            <!-- BEGIN: Block Dropdown -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Block Dropdown</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="space-y-3">
                            <div class="dropdown relative">
                                <button class="btn flex justify-center w-full btn-primary items-center" type="button" id="blockDropdownMenuButton1" data-bs-toggle="dropdown" aria-expanded="false"> primary
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class=" dropdown-menu min-w-full absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                            z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative">
                                <button class="btn flex justify-center w-full btn-outline-primary items-center" type="button" id="blockDropdownMenuButton2" data-bs-toggle="dropdown" aria-expanded="false"> primary
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                                </button>
                                <ul class=" dropdown-menu min-w-full absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                            z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                            <div class="dropdown relative">
                                <button class="btn inline-flex justify-center btn-primary items-center w-full cursor-default relative pr-14" type="button" id="blockDropdownMenuButton3" data-bs-toggle="dropdown" aria-expanded="false"> primary <span class="cursor-pointer absolute ltr:border-l rtl:border-r border-slate-100 h-full ltr:right-0 rtl:left-0 px-2 flex
                                                items-center justify-center leading-none">
                      <iconify-icon class="leading-none text-xl" icon="ic:round-keyboard-arrow-down"></iconify-icon>
                    </span> </button>
                                <ul class=" dropdown-menu min-w-full absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow
                                            z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white">
                                        Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white">
                                        Another Action</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white">
                                        Something else here</a> </li>
                                    <li> <a href="#" class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                                    dark:hover:text-white border-t border-slate-100 dark:border-slate-800">
                                        Sign out</a> </li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Block Dropdown -->
        </div>
    </div>
</x-app-layout>
