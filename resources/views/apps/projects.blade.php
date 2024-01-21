<x-app-layout>
    <div class="space-y-8">
        {{-- <div>--}}
        {{-- <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />--}}
        {{-- </div>--}}

        <div class="md:flex justify-between items-center">
            <div>
                Projects
            </div>
            <div class="flex flex-wrap ">
              <ul class="nav nav-pills flex items-center flex-wrap list-none pl-0 mr-4" id="pills-tabVertical" role="tablist">
                <li class="nav-item flex-grow text-center" role="presentation">

                  <button class="btn inline-flex justify-center btn-white dark:bg-slate-700 dark:text-slate-300 m-1 active" id="pills-list-tab" data-bs-toggle="pill" data-bs-target="#pills-list" role="tab" aria-controls="pills-list" aria-selected="false">
                    <span class="flex items-center">
                      <iconify-icon class="text-xl ltr:mr-2 rtl:ml-2" icon="heroicons-outline:clipboard-list"></iconify-icon>
                      <span>List View</span>
                    </span>
                  </button>
                  <button class="btn inline-flex justify-center btn-white dark:bg-slate-700 dark:text-slate-300 m-1" id="pills-grid-tab" data-bs-toggle="pill" data-bs-target="#pills-grid" role="tab" aria-controls="pills-grid" aria-selected="true">
                    <span class="flex items-center">
                      <iconify-icon class="text-xl ltr:mr-2 rtl:ml-2" icon="heroicons-outline:view-grid"></iconify-icon>
                      <span>Grid View</span>
                    </span>
                  </button>

                </li>
              </ul>
              <button class="btn inline-flex justify-center btn-white dark:bg-slate-700 dark:text-slate-300 m-1 ">
                <span class="flex items-center">
                  <iconify-icon class="text-xl ltr:mr-2 rtl:ml-2" icon="heroicons-outline:filter"></iconify-icon>
                  <span>On Going</span>
                </span>
              </button>
              <button class="btn inline-flex justify-center btn-dark dark:bg-slate-700 dark:text-slate-300 m-1 ">
                <span class="flex items-center">
                  <iconify-icon class="text-xl ltr:mr-2 rtl:ml-2" icon="ph:plus-bold"></iconify-icon>
                  <span>Add Project</span>
                </span>
              </button>
            </div>
        </div>

        <div class="tab-content mt-6" id="pills-tabContent">
        <div class="tab-pane fade show active" id="pills-list" role="tabpanel" aria-labelledby="pills-list-tab">
            <div class="tab-content">
            <div class="card">
                <div class="card-body px-6 rounded overflow-hidden">
                <div class="overflow-x-auto -mx-6">
                    <div class="inline-block min-w-full align-middle">
                    <div class="overflow-hidden ">
                        <table class="min-w-full divide-y divide-slate-100 table-fixed dark:divide-slate-700 ">
                        <thead class="bg-slate-200 dark:bg-slate-700">
                            <tr>
                            <th scope="col" class="table-th ">
                                NAME
                            </th>
                            <th scope="col" class="table-th ">
                                START DATE
                            </th>
                            <th scope="col" class="table-th ">
                                END DATE
                            </th>
                            <th scope="col" class="table-th ">
                                ASSIGNED
                            </th>
                            <th scope="col" class="table-th ">
                                STATUS
                            </th>
                            <th scope="col" class="table-th ">
                                ACTION
                            </th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-slate-100 dark:bg-slate-800 dark:divide-slate-700">
                            <tr class="even:bg-slate-50 dark:even:bg-slate-700">
                            <td class="table-td">
                                <div class="flex space-x-3 items-center text-left rtl:space-x-reverse">
                                <div class="flex-none">
                                    <div class="h-10 w-10 rounded-full text-sm bg-[#E0EAFF] dark:bg-slate-700 flex flex-col items-center justify-center font-medium -tracking-[1px]">
                                    Ma
                                    </div>
                                </div>
                                <div class="flex-1 font-medium text-sm leading-4 whitespace-nowrap">
                                    Management Dashboard
                                </div>
                                </div>
                            </td>
                            <td class="table-td">
                                <span class="block date-text">2022-10-03</span>
                            </td>
                            <td class="table-td">
                                <span class="block date-text">2022-10-10</span>
                            </td>
                            <td class="table-td">
                                <div class="flex justify-start -space-x-1.5 rtl:space-x-reverse">
                                <div class="h-6 w-6 rounded-full ring-1 ring-slate-100">
                                    <img src="images/post/c1.png" alt="Image" class="w-full h-full rounded-full">
                                </div>
                                <div class="h-6 w-6 rounded-full ring-1 ring-slate-100">
                                    <img src="images/post/c2.png" alt="Image" class="w-full h-full rounded-full">
                                </div>
                                <div class="h-6 w-6 rounded-full ring-1 ring-slate-100">
                                    <img src="images/post/c3.png" alt="Image" class="w-full h-full rounded-full">
                                </div>
                                <div class="bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-300 text-xs ring-2 ring-slate-100 dark:ring-slate-700 rounded-full h-6 w-6 flex flex-col justify-center items-center">
                                    +2
                                </div>
                                </div>
                            </td>
                            <td class="table-td">
                                <div class="w-full bg-slate-100 h-2 rounded-xl overflow-hidden">
                                <div class="bg-primary-500 progress-bar h-full rounded-xl" style="width: 0%"></div>
                                </div>
                            </td>
                            <td class="table-td">
                                <div class="dropstart relative">
                                <button class="inline-flex justify-center items-center" type="button" id="tableDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false">
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="heroicons-outline:dots-vertical"></iconify-icon>
                                </button>
                                <ul class="dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li>
                                    <a href="project-details.html" class="hover:bg-slate-900 dark:hover:bg-slate-600 dark:hover:bg-opacity-70 hover:text-white w-full border-b border-b-gray-500 border-opacity-10 px-4 py-2 text-sm dark:text-slate-300  last:mb-0 cursor-pointer first:rounded-t last:rounded-b flex space-x-2 items-center capitalize  rtl:space-x-reverse">
                                        <iconify-icon icon="heroicons-outline:eye"></iconify-icon>
                                        <span>View</span></a>
                                    </li>
                                    <li>
                                    <a href="#" data-bs-toggle="modal" data-bs-target="#editModal" class="hover:bg-slate-900 dark:hover:bg-slate-600 dark:hover:bg-opacity-70 hover:text-white w-full border-b border-b-gray-500 border-opacity-10 px-4 py-2 text-sm dark:text-slate-300 last:mb-0 cursor-pointer first:rounded-t last:rounded-b flex space-x-2 items-center capitalize rtl:space-x-reverse">
                                        <iconify-icon icon="clarity:note-edit-line"></iconify-icon>
                                        <span>Edit</span></a>
                                    </li>
                                    <li>
                                    <a href="#" class="hover:bg-slate-900 dark:hover:bg-slate-600 dark:hover:bg-opacity-70 hover:text-white w-full border-b border-b-gray-500 border-opacity-10 px-4 py-2 text-sm dark:text-slate-300 last:mb-0 cursor-pointer first:rounded-t last:rounded-b flex space-x-2 items-center capitalize rtl:space-x-reverse">
                                        <iconify-icon icon="fluent:delete-28-regular"></iconify-icon>
                                        <span>Delete</span></a>
                                    </li>
                                </ul>
                                </div>
                            </td>
                            </tr>
                            <tr class="even:bg-slate-50 dark:even:bg-slate-700">
                            <td class="table-td">
                                <div class="flex space-x-3 items-center text-left rtl:space-x-reverse">
                                <div class="flex-none">
                                    <div class="h-10 w-10 rounded-full text-sm bg-[#E0EAFF] dark:bg-slate-700 flex flex-col items-center justify-center font-medium -tracking-[1px]">
                                    Ma
                                    </div>
                                </div>
                                <div class="flex-1 font-medium text-sm leading-4 whitespace-nowrap">
                                    Management Dashboard
                                </div>
                                </div>
                            </td>
                            <td class="table-td">
                                <span class="block date-text">2022-10-03</span>
                            </td>
                            <td class="table-td">
                                <span class="block date-text">2022-10-10</span>
                            </td>
                            <td class="table-td">
                                <div class="flex justify-start -space-x-1.5 rtl:space-x-reverse">
                                <div class="h-6 w-6 rounded-full ring-1 ring-slate-100">
                                    <img src="images/post/c1.png" alt="Image" class="w-full h-full rounded-full">
                                </div>
                                <div class="h-6 w-6 rounded-full ring-1 ring-slate-100">
                                    <img src="images/post/c2.png" alt="Image" class="w-full h-full rounded-full">
                                </div>
                                <div class="h-6 w-6 rounded-full ring-1 ring-slate-100">
                                    <img src="images/post/c3.png" alt="Image" class="w-full h-full rounded-full">
                                </div>
                                <div class="bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-300 text-xs ring-2 ring-slate-100 dark:ring-slate-700 rounded-full h-6 w-6 flex flex-col justify-center items-center">
                                    +2
                                </div>
                                </div>
                            </td>
                            <td class="table-td">
                                <div class="w-full bg-slate-100 h-2 rounded-xl overflow-hidden">
                                <div class="bg-primary-500 progress-bar h-full rounded-xl" style="width: 0%"></div>
                                </div>
                            </td>
                            <td class="table-td">
                                <div class="dropstart relative">
                                <button class="inline-flex justify-center items-center" type="button" id="tableDropdownMenuButton2" data-bs-toggle="dropdown" aria-expanded="false">
                                    <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="heroicons-outline:dots-vertical"></iconify-icon>
                                </button>
                                <ul class="dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                    <li>
                                    <a href="project-details.html" class="hover:bg-slate-900 dark:hover:bg-slate-600 dark:hover:bg-opacity-70 hover:text-white w-full border-b border-b-gray-500 border-opacity-10 px-4 py-2 text-sm dark:text-slate-300  last:mb-0 cursor-pointer first:rounded-t last:rounded-b flex space-x-2 items-center capitalize  rtl:space-x-reverse">
                                        <iconify-icon icon="heroicons-outline:eye"></iconify-icon>
                                        <span>View</span></a>
                                    </li>
                                    <li>
                                    <a href="#" data-bs-toggle="modal" data-bs-target="#editModal" class="hover:bg-slate-900 dark:hover:bg-slate-600 dark:hover:bg-opacity-70 hover:text-white w-full border-b border-b-gray-500 border-opacity-10 px-4 py-2 text-sm dark:text-slate-300 last:mb-0 cursor-pointer first:rounded-t last:rounded-b flex space-x-2 items-center capitalize rtl:space-x-reverse">
                                        <iconify-icon icon="clarity:note-edit-line"></iconify-icon>
                                        <span>Edit</span></a>
                                    </li>
                                    <li>
                                    <a href="#" class="hover:bg-slate-900 dark:hover:bg-slate-600 dark:hover:bg-opacity-70 hover:text-white w-full border-b border-b-gray-500 border-opacity-10 px-4 py-2 text-sm dark:text-slate-300 last:mb-0 cursor-pointer first:rounded-t last:rounded-b flex space-x-2 items-center capitalize rtl:space-x-reverse">
                                        <iconify-icon icon="fluent:delete-28-regular"></iconify-icon>
                                        <span>Delete</span></a>
                                    </li>
                                </ul>
                                </div>
                            </td>
                            </tr>
                        </tbody>
                        </table>
                    </div>
                    </div>
                </div>
                <div class=" flex flex-wrap items-center justify-between space-x-2 py-4">
                    <div>
                    <div class="text-sm font-medium text-slate-600 dark:text-slate-300">Go
                        <input type="text" class="form-control !inline-block border max-w-[50px] px-2 py-2 text-center mr-2 " value="1">
                        <span>Page 1 of 1</span></div>
                    </div>
                    <div class="card-text h-full space-y-10">
                    <ul class="list-none">
                        <li class="inline-block">
                        <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                        dark:text-white rounded mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                        duration-300 relative top-[2px] pl-2">
                            <iconify-icon icon="material-symbols:arrow-back-ios-rounded"></iconify-icon>
                        </a>
                        </li>
                        <li class="inline-block">
                        <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                        dark:text-white rounded mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                        duration-300 p-active">
                            1</a>
                        </li>
                        <li class="inline-block">
                        <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                        dark:text-white rounded mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                        duration-300 ">
                            2</a>
                        </li>
                        <li class="inline-block">
                        <a href="#" class="flex items-center justify-center w-6 h-6 bg-slate-100 dark:bg-slate-700 dark:hover:bg-black-500 text-slate-800
                                        dark:text-white rounded mx-1 hover:bg-black-500 hover:text-white text-sm font-Inter font-medium transition-all
                                        duration-300 relative top-[2px]">
                            <iconify-icon icon="material-symbols:arrow-forward-ios-rounded"></iconify-icon>
                        </a>
                        </li>
                    </ul>
                    </div>
                </div>
                </div>
            </div>
            </div>
        </div>
        <div class="tab-pane fade " id="pills-grid" role="tabpanel" aria-labelledby="pills-grid-tab">
            <div class="grid xl:grid-cols-3 md:grid-cols-2 grid-cols-1 gap-5 ">
            <div class="card rounded-md bg-white dark:bg-slate-800 shadow-base custom-class card-body p-6">
                <header class="flex justify-between items-end">
                <div class="flex space-x-4 items-center rtl:space-x-reverse">
                    <div class="flex-none">
                    <div class="h-10 w-10 rounded-md text-lg bg-slate-100 text-slate-900 dark:bg-slate-600 dark:text-slate-200 flex flex-col items-center justify-center font-normal capitalize">
                        Bu
                    </div>
                    </div>
                    <div class="font-medium text-base leading-6">
                    <div class="dark:text-slate-200 text-slate-900 max-w-[160px] truncate">
                        Business Dashboard
                    </div>
                    </div>
                </div>
                <div>
                    <div class="dropstart relative">
                    <button class="inline-flex justify-center items-center" type="button" id="tableDropdownMenuButton3" data-bs-toggle="dropdown" aria-expanded="false">
                        <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="heroicons-outline:dots-vertical"></iconify-icon>
                    </button>
                    <ul class="dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                        <li>
                        <a href="project-details.html" class="hover:bg-slate-900 dark:hover:bg-slate-600 dark:hover:bg-opacity-70 hover:text-white
                        w-full border-b border-b-gray-500 border-opacity-10 px-4 py-2 text-sm dark:text-slate-300  last:mb-0 cursor-pointer first:rounded-t last:rounded-b flex space-x-2 items-center capitalize  rtl:space-x-reverse">
                            <iconify-icon icon="heroicons-outline:eye"></iconify-icon>
                            <span>View</span></a>
                        </li>
                        <li>
                        <a href="#" data-bs-toggle="modal" data-bs-target="#editModal" class="hover:bg-slate-900 dark:hover:bg-slate-600 dark:hover:bg-opacity-70 hover:text-white w-full border-b border-b-gray-500 border-opacity-10 px-4 py-2 text-sm dark:text-slate-300 last:mb-0 cursor-pointer first:rounded-t last:rounded-b flex space-x-2 items-center capitalize rtl:space-x-reverse">
                            <iconify-icon icon="clarity:note-edit-line"></iconify-icon>
                            <span>Edit</span></a>
                        </li>
                        <li>
                        <a href="#" class="hover:bg-slate-900 dark:hover:bg-slate-600 dark:hover:bg-opacity-70 hover:text-white w-full border-b border-b-gray-500 border-opacity-10 px-4 py-2 text-sm dark:text-slate-300 last:mb-0 cursor-pointer first:rounded-t last:rounded-b flex space-x-2 items-center capitalize rtl:space-x-reverse">
                            <iconify-icon icon="fluent:delete-28-regular"></iconify-icon>
                            <span>Delete</span></a>
                        </li>
                    </ul>
                    </div>
                </div>
                </header>
                <div class="text-slate-600 dark:text-slate-400 text-sm pt-4 pb-8"></div>
                <div class="flex space-x-4 rtl:space-x-reverse">
                <div>
                    <span class="block date-label">Start date</span>
                    <span class="block date-text">2022-10-03</span>
                </div>
                <div>
                    <span class="block date-label">Start date</span>
                    <span class="block date-text">2023-03-08</span>
                </div>
                </div>
                <div class="ltr:text-right rtl:text-left text-xs text-slate-600 dark:text-slate-300 mb-1 font-medium">
                50%
                </div>
                <div class="w-full bg-slate-200 h-2 rounded-xl overflow-hidden">
                <div class="bg-primary-500 progress-bar h-full rounded-xl" style="width: 0%"></div>
                </div>
                <div class="grid grid-cols-2 gap-4 mt-6">
                <div>
                    <div class="text-slate-400 dark:text-slate-400 text-sm font-normal mb-3">
                    Assigned to
                    </div>
                    <div class="flex justify-start -space-x-1.5 rtl:space-x-reverse">
                    <div class="h-6 w-6 rounded-full ring-1 ring-slate-100">
                        <img src="images/post/c1.png" alt="Image" class="w-full h-full rounded-full">
                    </div>
                    <div class="h-6 w-6 rounded-full ring-1 ring-slate-100">
                        <img src="images/post/c2.png" alt="Image" class="w-full h-full rounded-full">
                    </div>
                    <div class="h-6 w-6 rounded-full ring-1 ring-slate-100">
                        <img src="images/post/c3.png" alt="Image" class="w-full h-full rounded-full">
                    </div>
                    <div class="bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-300 text-xs ring-2 ring-slate-100 dark:ring-slate-700 rounded-full h-6 w-6 flex flex-col justify-center items-center">
                        +2
                    </div>
                    </div>
                </div>

                <div class="ltr:text-right rtl:text-left">
                    <span class="inline-flex items-center space-x-1 bg-danger-500 bg-opacity-[0.16] text-danger-500 text-xs font-normal px-2 py-1 rounded-full rtl:space-x-reverse">
                    <span>
                        <iconify-icon icon="heroicons-outline:clipboard-list"></iconify-icon>
                    </span>
                    <span>2</span>
                    <span>days left</span>
                    </span>
                </div>
                </div>
            </div>
            <div class="card rounded-md bg-white dark:bg-slate-800 shadow-base custom-class card-body p-6">
                <header class="flex justify-between items-end">
                <div class="flex space-x-4 items-center rtl:space-x-reverse">
                    <div class="flex-none">
                    <div class="h-10 w-10 rounded-md text-lg bg-slate-100 text-slate-900 dark:bg-slate-600 dark:text-slate-200 flex flex-col items-center justify-center font-normal capitalize">
                        Ma
                    </div>
                    </div>
                    <div class="font-medium text-base leading-6">
                    <div class="dark:text-slate-200 text-slate-900 max-w-[160px] truncate">
                        Management Dashboard
                    </div>
                    </div>
                </div>
                <div>
                    <div class="dropstart relative">
                    <button class="inline-flex justify-center items-center" type="button" id="tableDropdownMenuButton4" data-bs-toggle="dropdown" aria-expanded="false">
                        <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="heroicons-outline:dots-vertical"></iconify-icon>
                    </button>
                    <ul class="dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                        <li>
                        <a href="project-details.html" class="hover:bg-slate-900 dark:hover:bg-slate-600 dark:hover:bg-opacity-70 hover:text-white
                        w-full border-b border-b-gray-500 border-opacity-10 px-4 py-2 text-sm dark:text-slate-300  last:mb-0 cursor-pointer first:rounded-t last:rounded-b flex space-x-2 items-center capitalize  rtl:space-x-reverse">
                            <iconify-icon icon="heroicons-outline:eye"></iconify-icon>
                            <span>View</span></a>
                        </li>
                        <li>
                        <a href="#" data-bs-toggle="modal" data-bs-target="#editModal" class="hover:bg-slate-900 dark:hover:bg-slate-600 dark:hover:bg-opacity-70 hover:text-white w-full border-b border-b-gray-500 border-opacity-10 px-4 py-2 text-sm dark:text-slate-300 last:mb-0 cursor-pointer first:rounded-t last:rounded-b flex space-x-2 items-center capitalize rtl:space-x-reverse">
                            <iconify-icon icon="clarity:note-edit-line"></iconify-icon>
                            <span>Edit</span></a>
                        </li>
                        <li>
                        <a href="#" class="hover:bg-slate-900 dark:hover:bg-slate-600 dark:hover:bg-opacity-70 hover:text-white w-full border-b border-b-gray-500 border-opacity-10 px-4 py-2 text-sm dark:text-slate-300 last:mb-0 cursor-pointer first:rounded-t last:rounded-b flex space-x-2 items-center capitalize rtl:space-x-reverse">
                            <iconify-icon icon="fluent:delete-28-regular"></iconify-icon>
                            <span>Delete</span></a>
                        </li>
                    </ul>
                    </div>
                </div>
                </header>
                <div class="text-slate-600 dark:text-slate-400 text-sm pt-4 pb-8"></div>
                <div class="flex space-x-4 rtl:space-x-reverse">
                <div>
                    <span class="block date-label">Start date</span>
                    <span class="block date-text">2022-10-03</span>
                </div>
                <div>
                    <span class="block date-label">Start date</span>
                    <span class="block date-text">2023-03-08</span>
                </div>
                </div>
                <div class="ltr:text-right rtl:text-left text-xs text-slate-600 dark:text-slate-300 mb-1 font-medium">
                50%
                </div>
                <div class="w-full bg-slate-200 h-2 rounded-xl overflow-hidden">
                <div class="bg-primary-500 progress-bar h-full rounded-xl" style="width: 0%"></div>
                </div>
                <div class="grid grid-cols-2 gap-4 mt-6">
                <div>
                    <div class="text-slate-400 dark:text-slate-400 text-sm font-normal mb-3">
                    Assigned to
                    </div>
                    <div class="flex justify-start -space-x-1.5 rtl:space-x-reverse">
                    <div class="h-6 w-6 rounded-full ring-1 ring-slate-100">
                        <img src="images/post/c1.png" alt="Image" class="w-full h-full rounded-full">
                    </div>
                    <div class="h-6 w-6 rounded-full ring-1 ring-slate-100">
                        <img src="images/post/c2.png" alt="Image" class="w-full h-full rounded-full">
                    </div>
                    <div class="h-6 w-6 rounded-full ring-1 ring-slate-100">
                        <img src="images/post/c3.png" alt="Image" class="w-full h-full rounded-full">
                    </div>
                    <div class="bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-300 text-xs ring-2 ring-slate-100 dark:ring-slate-700 rounded-full h-6 w-6 flex flex-col justify-center items-center">
                        +2
                    </div>
                    </div>
                </div>

                <div class="ltr:text-right rtl:text-left">
                    <span class="inline-flex items-center space-x-1 bg-danger-500 bg-opacity-[0.16] text-danger-500 text-xs font-normal px-2 py-1 rounded-full rtl:space-x-reverse">
                    <span>
                        <iconify-icon icon="heroicons-outline:clipboard-list"></iconify-icon>
                    </span>
                    <span>2</span>
                    <span>days left</span>
                    </span>
                </div>
                </div>
            </div>
            </div>
        </div>
        </div>

        <div class="modal fade fixed top-0 left-0 hidden w-full h-full outline-none overflow-x-hidden overflow-y-auto" id="editModal" tabindex="-1" aria-labelledby="editModalLabel" aria-hidden="true">
        <div class="modal-dialog relative w-auto pointer-events-none">
            <div class="modal-content border-none shadow-lg relative flex flex-col lg:w-[576px] w-full pointer-events-auto bg-white bg-clip-padding
                                                rounded-md outline-none text-current">
            <div class="relative bg-white rounded-lg shadow dark:bg-slate-700">
                <!-- Modal header -->
                <div class="flex items-center justify-between p-5 border-b rounded-t dark:border-slate-600 bg-black-500">
                <h3 class="text-base font-medium text-white dark:text-white capitalize">
                    Edit Project
                </h3>
                <button type="button" class="text-slate-400 bg-transparent hover:text-slate-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center
                                                            dark:hover:bg-slate-600 dark:hover:text-white" data-bs-dismiss="modal">
                    <svg aria-hidden="true" class="w-5 h-5" fill="#ffffff" viewbox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                    </svg>
                    <span class="sr-only">Close modal</span>
                </button>
                </div>
                <!-- Modal body -->
                <div class="p-6 space-y-4">
                <form class="flex flex-col space-y-3">
                    <div class="input-area">
                    <div class="relative">
                        <input id="name" type="text" class="form-control pr-9" placeholder="Username">
                    </div>
                    <span id="nameErrorMsg" class="font-Inter text-sm text-danger-500 pt-2 hidden mt-1">This is valid state.</span>
                    </div>
                    <div class="flex items-center justify-between space-x-4">
                    <div class="w-full">
                        <label for="default-picker" class=" form-label">Start Date</label>
                        <input class="form-control py-2 flatpickr flatpickr-input active" id="default-picker" value="" type="text" readonly="readonly">
                    </div>
                    <div class="w-full">
                        <label for="default-picker" class=" form-label">End Date</label>
                        <input class="form-control py-2 flatpickr flatpickr-input active" id="default-picker" value="" type="text" readonly="readonly">
                    </div>
                    </div>
                    <div>
                    <label for="basicSelect" class="form-label">Assignee</label>
                    <select name="basicSelect" id="basicSelect" class="form-control w-full mt-2">
                        <option selected="Selected" disabled="disabled" value="none" class="select2 py-1 inline-block font-Inter font-normal text-sm text-slate-600">Select an option</option>
                        <option value="option1" class="py-1 inline-block font-Inter font-normal text-sm text-slate-600">Jhon Doe</option>
                        <option value="option2" class="py-1 inline-block font-Inter font-normal text-sm text-slate-600">Jhon Smith</option>
                        <option value="option3" class="py-1 inline-block font-Inter font-normal text-sm text-slate-600">Grane Smith</option>
                    </select>
                    </div>
                    <div>
                    <label for="basicSelect" class="form-label">Tag</label>
                    <select name="basicSelect" id="basicSelect" class="form-control w-full mt-2">
                        <option selected="Selected" disabled="disabled" value="none" class="select2 py-1 inline-block font-Inter font-normal text-sm text-slate-600">Select an option</option>
                        <option value="option1" class="py-1 inline-block font-Inter font-normal text-sm text-slate-600">Admin</option>
                        <option value="option2" class="py-1 inline-block font-Inter font-normal text-sm text-slate-600">Dashboard</option>
                        <option value="option3" class="py-1 inline-block font-Inter font-normal text-sm text-slate-600">User Friendly</option>
                    </select>
                    </div>
                    <div>
                    <label for="description" class="form-label">Description</label>
                    <textarea name="description" class="form-control" id="description" rows="3"></textarea>
                    </div>
                    <div class="flex items-center justify-end rounded-b dark:border-slate-600">
                    <button data-bs-dismiss="modal" class="btn inline-flex justify-center text-white bg-black-500">Update</button>
                    </div>
                </form>
                </div>
            </div>
            </div>
        </div>
        </div>
    </div>

    @push('scripts')

    @endpush
</x-app-layout>
