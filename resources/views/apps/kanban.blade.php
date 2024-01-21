<x-app-layout>
    <div class="space-y-8">
        {{-- <div>--}}
        {{-- <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />--}}
        {{-- </div>--}}

        <div class="space-y-6">
            <div class="flex flex-wrap justify-between items-center mb-4">
              <h4 class="font-medium lg:text-2xl text-xl capitalize text-slate-900 inline-block ltr:pr-4 rtl:pl-4 mb-1 sm:mb-0">Kanban</h4>
              <div class="flex space-x-4 justify-end items-center rtl:space-x-reverse">
                <button class="btn inline-flex justify-center btn-dark dark:bg-slate-800 m-1 ">
                  <span class="flex items-center">
                    <iconify-icon class="text-xl ltr:mr-2 rtl:ml-2" icon="ph:plus-bold">
                    </iconify-icon>
                    <span>Add Board</span>
                  </span>
                </button>
              </div>
            </div>
            <div class="flex space-x-6 overflow-hidden overflow-x-auto pb-4 rtl:space-x-reverse">
              <div class="w-[320px] flex-none min-h-screen h-full rounded transition-all duration-100 shadow-none bg-slate-200 dark:bg-slate-700">
                <div class="relative flex justify-between items-center bg-white dark:bg-slate-800 rounded shadow-base px-6 py-5">
                  <span class="absolute left-0 top-1/2 -translate-y-1/2 h-8 w-[2px] bg-primary-500">
                  </span>
                  <h3 class="text-lg text-slate-900 dark:text-white font-medium capitalize">To Do</h3>
                  <div class="flex items-center space-x-2">
                    <button class="scale border border-slate-200 dark:border-slate-700 dark:text-slate-400 rounded h-6 w-6 flex flex-col items-center
                          justify-center text-base text-slate-600" data-tippy-content="Add Card" data-tippy-theme="dark">
                      <iconify-icon icon="ph:plus-bold">
                      </iconify-icon>
                    </button>
                    <button class="scale border border-slate-200 dark:border-slate-700 dark:text-slate-400 rounded h-6 w-6 flex flex-col items-center
                          justify-center text-base text-slate-600" data-tippy-content="Delete" data-tippy-theme="danger">
                      <iconify-icon icon="fluent:delete-20-regular">
                      </iconify-icon>
                    </button>
                  </div>
                </div>
                <div id="todo" class="h-full min-h-[calc(100vh-100px)] ">
                  <div class="px-2 py-4 h-full space-y-4 rounded-bl rounded-br cursor-grab">
                    <!-- BEGIN: Cards -->
                    <div class="card rounded-md bg-white dark:bg-slate-800 shadow-base custom-class card-body p-6">
                      <header class="flex justify-between items-end">
                        <div class="flex space-x-4 items-center rtl:space-x-reverse">
                          <div class="flex-none">
                            <div class="h-10 w-10 rounded-md text-lg bg-slate-100 text-slate-900 dark:bg-slate-600 dark:text-slate-200 flex flex-col items-center justify-center font-normal capitalize">Ma</div>
                          </div>
                          <div class="font-medium text-base leading-6">
                            <div class="dark:text-slate-200 text-slate-900 max-w-[160px] truncate">Management Dashboard</div>
                          </div>
                        </div>
                        <div>
                          <div class="dropstart relative">
                            <button class="inline-flex justify-center items-center" type="button" id="cardDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false">
                              <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="heroicons-outline:dots-vertical">
                              </iconify-icon>
                            </button>
                            <ul class="dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                              <li>
                                <a href="#" data-bs-toggle="modal" data-bs-target="#editModal" class="hover:bg-slate-900 dark:hover:bg-slate-600 dark:hover:bg-opacity-70 hover:text-white w-full border-b border-b-gray-500 border-opacity-10 px-4 py-2 text-sm dark:text-slate-300 last:mb-0 cursor-pointer first:rounded-t last:rounded-b flex space-x-2 items-center capitalize rtl:space-x-reverse">
                                  <iconify-icon icon="clarity:note-edit-line">
                                  </iconify-icon>
                                  <span>Edit</span>
                                </a>
                              </li>
                              <li>
                                <a href="#" class="hover:bg-slate-900 dark:hover:bg-slate-600 dark:hover:bg-opacity-70 hover:text-white w-full border-b border-b-gray-500 border-opacity-10 px-4 py-2 text-sm dark:text-slate-300 last:mb-0 cursor-pointer first:rounded-t last:rounded-b flex space-x-2 items-center capitalize rtl:space-x-reverse">
                                  <iconify-icon icon="fluent:delete-28-regular">
                                  </iconify-icon>
                                  <span>Delete</span>
                                </a>
                              </li>
                            </ul>
                          </div>
                        </div>
                      </header>
                      <p class="text-slate-600 dark:text-slate-400 text-sm py-4">Lorem, ipsum dolor sit amet conse ctetur adipisicing elit. Expedita id repellendus.</p>
                      <div class="flex space-x-4 rtl:space-x-reverse">
                        <div>
                          <span class="block date-label">Start date</span>
                          <span class="block date-text">03-02-2023</span>
                        </div>
                        <div>
                          <span class="block date-label">End date</span>
                          <span class="block date-text">03-03-2023</span>
                        </div>
                      </div>
                      <div class="ltr:text-right rtl:text-left text-xs text-slate-600 dark:text-slate-300 mb-1 font-medium">50%</div>
                      <div class="w-full bg-slate-200 h-2 rounded-xl overflow-hidden">
                        <div class="bg-primary-500 progress-bar h-full rounded-xl" style="width: 0%">
                        </div>
                      </div>
                      <div class="grid grid-cols-2 gap-4 mt-6">
                        <div>
                          <div class="text-slate-400 dark:text-slate-400 text-sm font-normal mb-3">Assigned to</div>
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
                            <div class="bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-300 text-xs ring-2 ring-slate-100 dark:ring-slate-700 rounded-full h-6 w-6 flex flex-col justify-center items-center">+2</div>
                          </div>
                        </div>
                        <div class="ltr:text-right rtl:text-left">
                          <span class="inline-flex items-center space-x-1 bg-danger-500 bg-opacity-[0.16] text-danger-500 text-xs font-normal px-2 py-1 rounded-full rtl:space-x-reverse">
                            <span>
                              <iconify-icon icon="heroicons-outline:clipboard-list">
                              </iconify-icon>
                            </span>
                            <span>2</span>
                            <span>days left</span>
                          </span>
                        </div>
                      </div>
                    </div>
                    <!-- END: Cards -->
                  </div>
                  <div class="px-2 py-4 h-full space-y-4 rounded-bl rounded-br cursor-grab ">
                    <!-- BEGIN: Cards -->
                    <div class="card rounded-md bg-white dark:bg-slate-800 shadow-base custom-class card-body p-6">
                      <header class="flex justify-between items-end">
                        <div class="flex space-x-4 items-center rtl:space-x-reverse">
                          <div class="flex-none">
                            <div class="h-10 w-10 rounded-md text-lg bg-slate-100 text-slate-900 dark:bg-slate-600 dark:text-slate-200 flex flex-col items-center justify-center font-normal capitalize">Ma</div>
                          </div>
                          <div class="font-medium text-base leading-6">
                            <div class="dark:text-slate-200 text-slate-900 max-w-[160px] truncate">Business Dashboard</div>
                          </div>
                        </div>
                        <div>
                          <div class="dropstart relative">
                            <button class="inline-flex justify-center items-center" type="button" id="cardDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false">
                              <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="heroicons-outline:dots-vertical">
                              </iconify-icon>
                            </button>
                            <ul class="dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                              <li>
                                <a href="#" data-bs-toggle="modal" data-bs-target="#editModal" class="hover:bg-slate-900 dark:hover:bg-slate-600 dark:hover:bg-opacity-70 hover:text-white w-full border-b border-b-gray-500 border-opacity-10 px-4 py-2 text-sm dark:text-slate-300 last:mb-0 cursor-pointer first:rounded-t last:rounded-b flex space-x-2 items-center capitalize rtl:space-x-reverse">
                                  <iconify-icon icon="clarity:note-edit-line">
                                  </iconify-icon>
                                  <span>Edit</span>
                                </a>
                              </li>
                              <li>
                                <a href="#" class="hover:bg-slate-900 dark:hover:bg-slate-600 dark:hover:bg-opacity-70 hover:text-white w-full border-b border-b-gray-500 border-opacity-10 px-4 py-2 text-sm dark:text-slate-300 last:mb-0 cursor-pointer first:rounded-t last:rounded-b flex space-x-2 items-center capitalize rtl:space-x-reverse">
                                  <iconify-icon icon="fluent:delete-28-regular">
                                  </iconify-icon>
                                  <span>Delete</span>
                                </a>
                              </li>
                            </ul>
                          </div>
                        </div>
                      </header>
                      <p class="text-slate-600 dark:text-slate-400 text-sm py-4">Lorem, ipsum dolor sit amet conse ctetur adipisicing elit. Expedita id repellendus.</p>
                      <div class="flex space-x-4 rtl:space-x-reverse">
                        <div>
                          <span class="block date-label">Start date</span>
                          <span class="block date-text">01-04-2023</span>
                        </div>
                        <div>
                          <span class="block date-label">End date</span>
                          <span class="block date-text">15-06-2023</span>
                        </div>
                      </div>
                      <div class="ltr:text-right rtl:text-left text-xs text-slate-600 dark:text-slate-300 mb-1 font-medium">50%</div>
                      <div class="w-full bg-slate-200 h-2 rounded-xl overflow-hidden">
                        <div class="bg-primary-500 progress-bar h-full rounded-xl" style="width: 0%">
                        </div>
                      </div>
                      <div class="grid grid-cols-2 gap-4 mt-6">
                        <div>
                          <div class="text-slate-400 dark:text-slate-400 text-sm font-normal mb-3">Assigned to</div>
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
                            <div class="bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-300 text-xs ring-2 ring-slate-100 dark:ring-slate-700 rounded-full h-6 w-6 flex flex-col justify-center items-center">+2</div>
                          </div>
                        </div>
                        <div class="ltr:text-right rtl:text-left">
                          <span class="inline-flex items-center space-x-1 bg-danger-500 bg-opacity-[0.16] text-danger-500 text-xs font-normal px-2 py-1 rounded-full rtl:space-x-reverse">
                            <span>
                              <iconify-icon icon="heroicons-outline:clipboard-list">
                              </iconify-icon>
                            </span>
                            <span>2</span>
                            <span>days left</span>
                          </span>
                        </div>
                      </div>
                    </div>
                    <!-- END: Cards -->
                  </div>
                </div>
              </div>
              <div class="w-[320px] flex-none min-h-screen h-full rounded transition-all duration-100 shadow-none bg-slate-200 dark:bg-slate-700">
                <div class="relative flex justify-between items-center bg-white dark:bg-slate-800 rounded shadow-base px-6 py-5">
                  <span class="absolute left-0 top-1/2 -translate-y-1/2 h-8 w-[2px] bg-primary-500">
                  </span>
                  <h3 class="text-lg text-slate-900 dark:text-white font-medium capitalize">In Progress</h3>
                  <div class="flex items-center space-x-2">
                    <button class="scale border border-slate-200 dark:border-slate-700 dark:text-slate-400 rounded h-6 w-6 flex flex-col items-center
                          justify-center text-base text-slate-600" data-tippy-content="Add Card" data-tippy-theme="dark">
                      <iconify-icon icon="ph:plus-bold">
                      </iconify-icon>
                    </button>
                    <button class="scale border border-slate-200 dark:border-slate-700 dark:text-slate-400 rounded h-6 w-6 flex flex-col items-center
                          justify-center text-base text-slate-600" data-tippy-content="Delete" data-tippy-theme="danger">
                      <iconify-icon icon="fluent:delete-20-regular">
                      </iconify-icon>
                    </button>
                  </div>
                </div>
                <div id="progress" class="h-full min-h-[calc(100vh-100px)] ">
                  <div class="px-2 py-4 h-full space-y-4 rounded-bl rounded-br cursor-grab ">
                    <!-- BEGIN: Cards -->
                    <div class="card rounded-md bg-white dark:bg-slate-800 shadow-base custom-class card-body p-6">
                      <header class="flex justify-between items-end">
                        <div class="flex space-x-4 items-center rtl:space-x-reverse">
                          <div class="flex-none">
                            <div class="h-10 w-10 rounded-md text-lg bg-slate-100 text-slate-900 dark:bg-slate-600 dark:text-slate-200 flex flex-col items-center justify-center font-normal capitalize">Ma</div>
                          </div>
                          <div class="font-medium text-base leading-6">
                            <div class="dark:text-slate-200 text-slate-900 max-w-[160px] truncate">Management Dashboard</div>
                          </div>
                        </div>
                        <div>
                          <div class="dropstart relative">
                            <button class="inline-flex justify-center items-center" type="button" id="cardDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false">
                              <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="heroicons-outline:dots-vertical">
                              </iconify-icon>
                            </button>
                            <ul class="dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                              <li>
                                <a href="#" data-bs-toggle="modal" data-bs-target="#editModal" class="hover:bg-slate-900 dark:hover:bg-slate-600 dark:hover:bg-opacity-70 hover:text-white w-full border-b border-b-gray-500 border-opacity-10 px-4 py-2 text-sm dark:text-slate-300 last:mb-0 cursor-pointer first:rounded-t last:rounded-b flex space-x-2 items-center capitalize rtl:space-x-reverse">
                                  <iconify-icon icon="clarity:note-edit-line">
                                  </iconify-icon>
                                  <span>Edit</span>
                                </a>
                              </li>
                              <li>
                                <a href="#" class="hover:bg-slate-900 dark:hover:bg-slate-600 dark:hover:bg-opacity-70 hover:text-white w-full border-b border-b-gray-500 border-opacity-10 px-4 py-2 text-sm dark:text-slate-300 last:mb-0 cursor-pointer first:rounded-t last:rounded-b flex space-x-2 items-center capitalize rtl:space-x-reverse">
                                  <iconify-icon icon="fluent:delete-28-regular">
                                  </iconify-icon>
                                  <span>Delete</span>
                                </a>
                              </li>
                            </ul>
                          </div>
                        </div>
                      </header>
                      <p class="text-slate-600 dark:text-slate-400 text-sm py-4">Lorem, ipsum dolor sit amet conse ctetur adipisicing elit. Expedita id repellendus.</p>
                      <div class="flex space-x-4 rtl:space-x-reverse">
                        <div>
                          <span class="block date-label">Start date</span>
                          <span class="block date-text">03-02-2023</span>
                        </div>
                        <div>
                          <span class="block date-label">End date</span>
                          <span class="block date-text">03-03-2023</span>
                        </div>
                      </div>
                      <div class="ltr:text-right rtl:text-left text-xs text-slate-600 dark:text-slate-300 mb-1 font-medium">50%</div>
                      <div class="w-full bg-slate-200 h-2 rounded-xl overflow-hidden">
                        <div class="bg-primary-500 progress-bar h-full rounded-xl" style="width: 0%">
                        </div>
                      </div>
                      <div class="grid grid-cols-2 gap-4 mt-6">
                        <div>
                          <div class="text-slate-400 dark:text-slate-400 text-sm font-normal mb-3">Assigned to</div>
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
                            <div class="bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-300 text-xs ring-2 ring-slate-100 dark:ring-slate-700 rounded-full h-6 w-6 flex flex-col justify-center items-center">+2</div>
                          </div>
                        </div>
                        <div class="ltr:text-right rtl:text-left">
                          <span class="inline-flex items-center space-x-1 bg-danger-500 bg-opacity-[0.16] text-danger-500 text-xs font-normal px-2 py-1 rounded-full rtl:space-x-reverse">
                            <span>
                              <iconify-icon icon="heroicons-outline:clipboard-list">
                              </iconify-icon>
                            </span>
                            <span>2</span>
                            <span>days left</span>
                          </span>
                        </div>
                      </div>
                    </div>
                    <!-- END: Cards -->
                  </div>
                </div>
              </div>
              <div class="w-[320px] flex-none min-h-screen h-full rounded transition-all duration-100 shadow-none bg-slate-200 dark:bg-slate-700">
                <div class="relative flex justify-between items-center bg-white dark:bg-slate-800 rounded shadow-base px-6 py-5">
                  <span class="absolute left-0 top-1/2 -translate-y-1/2 h-8 w-[2px] bg-primary-500">
                  </span>
                  <h3 class="text-lg text-slate-900 dark:text-white font-medium capitalize">Done</h3>
                  <div class="flex items-center space-x-2">
                    <button class="scale border border-slate-200 dark:border-slate-700 dark:text-slate-400 rounded h-6 w-6 flex flex-col items-center
                          justify-center text-base text-slate-600" data-tippy-content="Add Card" data-tippy-theme="dark">
                      <iconify-icon icon="ph:plus-bold">
                      </iconify-icon>
                    </button>
                    <button class="scale border border-slate-200 dark:border-slate-700 dark:text-slate-400 rounded h-6 w-6 flex flex-col items-center
                          justify-center text-base text-slate-600" data-tippy-content="Delete" data-tippy-theme="danger">
                      <iconify-icon icon="fluent:delete-20-regular">
                      </iconify-icon>
                    </button>
                  </div>
                </div>
                <div id="done" class="h-full min-h-[calc(100vh-100px)] ">
                  <div class="px-2 py-4 h-full space-y-4 rounded-bl rounded-br cursor-grab ">
                    <!-- BEGIN: Cards -->
                    <div class="card rounded-md bg-white dark:bg-slate-800 shadow-base custom-class card-body p-6">
                      <header class="flex justify-between items-end">
                        <div class="flex space-x-4 items-center rtl:space-x-reverse">
                          <div class="flex-none">
                            <div class="h-10 w-10 rounded-md text-lg bg-slate-100 text-slate-900 dark:bg-slate-600 dark:text-slate-200 flex flex-col items-center justify-center font-normal capitalize">Ma</div>
                          </div>
                          <div class="font-medium text-base leading-6">
                            <div class="dark:text-slate-200 text-slate-900 max-w-[160px] truncate">Management Dashboard</div>
                          </div>
                        </div>
                        <div>
                          <div class="dropstart relative">
                            <button class="inline-flex justify-center items-center" type="button" id="cardDropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false">
                              <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="heroicons-outline:dots-vertical">
                              </iconify-icon>
                            </button>
                            <ul class="dropdown-menu min-w-max absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700 shadow z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                              <li>
                                <a href="#" data-bs-toggle="modal" data-bs-target="#editModal" class="hover:bg-slate-900 dark:hover:bg-slate-600 dark:hover:bg-opacity-70 hover:text-white w-full border-b border-b-gray-500 border-opacity-10 px-4 py-2 text-sm dark:text-slate-300 last:mb-0 cursor-pointer first:rounded-t last:rounded-b flex space-x-2 items-center capitalize rtl:space-x-reverse">
                                  <iconify-icon icon="clarity:note-edit-line">
                                  </iconify-icon>
                                  <span>Edit</span>
                                </a>
                              </li>
                              <li>
                                <a href="#" class="hover:bg-slate-900 dark:hover:bg-slate-600 dark:hover:bg-opacity-70 hover:text-white w-full border-b border-b-gray-500 border-opacity-10 px-4 py-2 text-sm dark:text-slate-300 last:mb-0 cursor-pointer first:rounded-t last:rounded-b flex space-x-2 items-center capitalize rtl:space-x-reverse">
                                  <iconify-icon icon="fluent:delete-28-regular">
                                  </iconify-icon>
                                  <span>Delete</span>
                                </a>
                              </li>
                            </ul>
                          </div>
                        </div>
                      </header>
                      <p class="text-slate-600 dark:text-slate-400 text-sm py-4">Lorem, ipsum dolor sit amet conse ctetur adipisicing elit. Expedita id repellendus.</p>
                      <div class="flex space-x-4 rtl:space-x-reverse">
                        <div>
                          <span class="block date-label">Start date</span>
                          <span class="block date-text">03-02-2023</span>
                        </div>
                        <div>
                          <span class="block date-label">End date</span>
                          <span class="block date-text">03-03-2023</span>
                        </div>
                      </div>
                      <div class="ltr:text-right rtl:text-left text-xs text-slate-600 dark:text-slate-300 mb-1 font-medium">50%</div>
                      <div class="w-full bg-slate-200 h-2 rounded-xl overflow-hidden">
                        <div class="bg-primary-500 progress-bar h-full rounded-xl" style="width: 0%">
                        </div>
                      </div>
                      <div class="grid grid-cols-2 gap-4 mt-6">
                        <div>
                          <div class="text-slate-400 dark:text-slate-400 text-sm font-normal mb-3">Assigned to</div>
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
                            <div class="bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-300 text-xs ring-2 ring-slate-100 dark:ring-slate-700 rounded-full h-6 w-6 flex flex-col justify-center items-center">+2</div>
                          </div>
                        </div>
                        <div class="ltr:text-right rtl:text-left">
                          <span class="inline-flex items-center space-x-1 bg-danger-500 bg-opacity-[0.16] text-danger-500 text-xs font-normal px-2 py-1 rounded-full rtl:space-x-reverse">
                            <span>
                              <iconify-icon icon="heroicons-outline:clipboard-list">
                              </iconify-icon>
                            </span>
                            <span>2</span>
                            <span>days left</span>
                          </span>
                        </div>
                      </div>
                    </div>
                    <!-- END: Cards -->
                  </div>
                </div>
              </div>
            </div>
        </div>
        <div class="modal fade fixed top-0 left-0 hidden w-full h-full outline-none overflow-x-hidden overflow-y-auto" id="editModal" tabindex="-1" aria-labelledby="editModalLabel" aria-hidden="true">
        <div class="modal-dialog relative w-auto pointer-events-none">
            <div class="modal-content border-none shadow-lg relative flex flex-col lg:w-[576px] w-full pointer-events-auto bg-white
                bg-clip-padding rounded-md outline-none text-current">
            <div class="relative bg-white rounded-lg shadow dark:bg-slate-700">
                <!-- Modal header -->
                <div class="flex items-center justify-between p-5 border-b rounded-t dark:border-slate-600 bg-black-500">
                <h3 class="text-base font-medium text-white dark:text-white capitalize">Edit Project</h3>
                <button type="button" class="text-slate-400 bg-transparent hover:text-slate-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center
                        dark:hover:bg-slate-600 dark:hover:text-white" data-bs-dismiss="modal">
                    <svg aria-hidden="true" class="w-5 h-5" fill="#ffffff" viewbox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10
                            11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd">
                    </path>
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
                    <textarea name="description" class="form-control" id="description" rows="3">
                    </textarea>
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
        <script type="module">
            dragula([document.getElementById("todo"), document.getElementById("progress"), document.getElementById("done")]);
        </script>
    @endpush
</x-app-layout>
