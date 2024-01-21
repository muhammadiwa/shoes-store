<x-app-layout>
    <div class="space-y-8">
        <div>
          <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="grid xl:grid-cols-2 grid-cols-1 gap-6">
            <div class="card">
              <div class="card-body flex flex-col p-6">
                <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                  <div class="flex-1">
                    <div class="card-title text-slate-900 dark:text-white">Basic Input Groups</div>
                  </div>
                </header>
                <div class="card-text h-full space-y-4">

                  <div class="input-area">
                    <div class="relative group">
                      <input type="text" class="form-control !pl-12" placeholder="Search">
                      <button class="absolute left-0 top-1/2 -translate-y-1/2 w-9 h-full border-r border-r-slate-200 dark:border-r-slate-700 flex items-center justify-center">
                        <iconify-icon icon="heroicons-solid:search"></iconify-icon>
                      </button>
                    </div>
                  </div>

                  <div class="input-area">
                    <div class="relative">
                      <input type="text" class="form-control !pr-12" placeholder="Search">
                      <button class="absolute right-0 top-1/2 -translate-y-1/2 w-9 h-full border-l border-l-slate-200 dark:border-l-slate-700 flex items-center justify-center">
                        <iconify-icon icon="heroicons-solid:search"></iconify-icon>
                      </button>
                    </div>
                  </div>

                  <div class="input-area">
                    <div class="relative">
                      <input type="text" class="form-control !pr-12" placeholder="Diasable Input Group" disabled="disabled">
                      <button class="absolute right-0 top-1/2 -translate-y-1/2 w-9 h-full border-l border-l-slate-200 dark:border-l-slate-800 flex items-center justify-center cursor-not-allowed" disabled="disabled">
                        <iconify-icon icon="heroicons-solid:search"></iconify-icon>
                      </button>
                    </div>
                  </div>

                  <div class="input-area">
                    <div class="relative">
                      <input type="text" class="form-control !pl-12" placeholder="Readonly Input Group" readonly="readonly">
                      <button class="absolute left-0 top-1/2 -translate-y-1/2 w-9 h-full border-r border-r-slate-200 dark:border-r-slate-700 flex items-center justify-center">
                        <iconify-icon icon="heroicons-solid:search"></iconify-icon>
                      </button>
                    </div>
                  </div>

                  <div class="input-area">
                    <div class="relative">
                      <input type="password" class="form-control" placeholder="Password">
                    </div>
                  </div>

                  <div class="input-area">
                    <div class="relative">
                      <input type="text" class="form-control !pl-12" placeholder="Username">
                      <span class="absolute left-0 top-1/2 -translate-y-1/2 w-9 h-full border-r border-r-slate-200 dark:border-r-slate-700 flex items-center justify-center">
                        @
                      </span>
                    </div>
                  </div>

                  <div class="input-area">
                    <div class="relative">
                      <input type="text" class="form-control !pr-32" placeholder="Username">
                      <span class="absolute right-0 top-1/2 px-3 -translate-y-1/2 h-full border-l border-l-slate-200 dark:border-r-slate-700 flex items-center justify-center">
                        @example.com
                      </span>
                    </div>
                  </div>

                  <div class="input-area">
                    <div class="relative">
                      <input type="text" class="form-control !pl-56" placeholder="Username">
                      <span class="absolute left-0 top-1/2 px-3 -translate-y-1/2 h-full border-r border-r-slate-200 dark:border-r-slate-700 flex items-center justify-center">
                        https://example.com/users/
                      </span>
                    </div>
                  </div>

                  <div class="input-area">
                    <div class="relative">
                      <input type="text" class="form-control !px-12" placeholder="Username">
                      <span class="absolute left-0 top-1/2 -translate-y-1/2 w-9 h-full border-r border-r-slate-200 dark:border-r-slate-700 flex items-center justify-center">
                        $
                      </span>
                      <span class="absolute right-0 top-1/2 -translate-y-1/2 w-9 h-full border-l border-l-slate-200 dark:border-r-slate-700 flex items-center justify-center">
                        .00
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-1 gap-6">
              <div class="card">
                <div class="card-body flex flex-col p-6">
                  <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                    <div class="flex-1">
                      <div class="card-title text-slate-900 dark:text-white">Sizing Options</div>
                    </div>
                  </header>
                  <div class="card-text h-full space-y-4">
                    <div class="input-area">
                      <label for="largeInput" class="mb-2 block cursor-pointer font-Inter font-medium capitalize text-slate-700 dark:text-slate-50 leading-6">Large Input</label>
                      <div class="relative">
                        <input type="text" class="form-control !pl-12 !text-lg" placeholder="Username">
                        <span class="absolute left-0 top-1/2 -translate-y-1/2 w-9 h-full text-xl border-r border-r-slate-200 dark:border-r-slate-700 flex items-center justify-center">
                          @
                        </span>
                      </div>
                    </div>
                    <div class="input-area">
                      <label for="defaultInput" class="mb-2 block cursor-pointer font-Inter font-medium capitalize text-slate-700 dark:text-slate-50 leading-6">Default Input</label>
                      <div class="relative">
                        <input type="text" class="form-control !pl-12" placeholder="Username">
                        <span class="absolute left-0 top-1/2 -translate-y-1/2 w-9 h-full border-r border-r-slate-200 dark:border-r-slate-700 flex items-center justify-center">
                          @
                        </span>
                      </div>
                    </div>
                    <div class="input-area">
                      <label for="smallInput" class="mb-2 block cursor-pointer font-Inter font-medium capitalize text-slate-700 dark:text-slate-50 leading-6">Small Input</label>
                      <div class="relative">
                        <input type="text" class="form-control !pl-12 !py-1 !text-xs" placeholder="Username">
                        <span class="absolute left-0 top-1/2 -translate-y-1/2 w-9 h-full text-xs border-r border-r-slate-200 dark:border-r-slate-700 flex items-center justify-center">
                          @
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div class="card">
                <div class="card-body flex flex-col p-6">
                  <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                    <div class="flex-1">
                      <div class="card-title text-slate-900 dark:text-white">Horizontal Form Label Sizing</div>
                    </div>
                  </header>
                  <div class="card-text h-full space-y-4">
                    <div class="input-area relative !pl-28">
                      <label for="largeInput" class="mb-2 absolute left-0 top-1/2 -translate-y-1/2 block cursor-pointer font-Inter font-medium capitalize text-slate-700 dark:text-slate-50 leading-6">Large Input</label>
                      <div class="relative">
                        <input type="text" class="form-control !pl-12 !text-lg" placeholder="Username">
                        <span class="absolute left-0 top-1/2 -translate-y-1/2 w-9 h-full text-xl border-r border-r-slate-200 dark:border-r-slate-700 flex items-center justify-center">
                          @
                        </span>
                      </div>
                    </div>
                    <div class="input-area relative !pl-28">
                      <label for="defaultInput" class="mb-2 absolute left-0 top-1/2 -translate-y-1/2 block cursor-pointer font-Inter font-medium capitalize text-slate-700 dark:text-slate-50 leading-6">Default Input</label>
                      <div class="relative">
                        <input type="text" class="form-control !pl-12" placeholder="Username">
                        <span class="absolute left-0 top-1/2 -translate-y-1/2 w-9 h-full text-sm border-r border-r-slate-200 dark:border-r-slate-700 flex items-center justify-center">
                          @
                        </span>
                      </div>
                    </div>
                    <div class="input-area relative pl-28">
                      <label for="smallInput" class="mb-2 absolute left-0 top-1/2 -translate-y-1/2 block cursor-pointer font-Inter font-medium capitalize text-slate-700 dark:text-slate-50 leading-6">Small Input</label>
                      <div class="relative">
                        <input type="text" class="form-control !pl-12 !text-xs !py-1" placeholder="Username">
                        <span class="absolute left-0 top-1/2 -translate-y-1/2 w-9 h-full text-xs border-r border-r-slate-200 dark:border-r-slate-700 flex items-center justify-center">
                          @
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div class="card xl:col-span-2">
              <div class="card-body flex flex-col p-6">
                <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                  <div class="flex-1">
                    <div class="card-title text-slate-900 dark:text-white">Basic Input Groups</div>
                  </div>
                </header>
                <div class="card-text h-full space-y-4">

                  <div class="input-area">
                    <div class="relative group">
                      <input type="text" class="form-control !pl-9" placeholder="Search">
                      <button class="absolute left-0 top-1/2 -translate-y-1/2 w-9 h-full border-none flex items-center justify-center">
                        <iconify-icon icon="heroicons-solid:search"></iconify-icon>
                      </button>
                    </div>
                  </div>

                  <div class="input-area">
                    <div class="relative">
                      <input type="text" class="form-control !pr-9" placeholder="Search">
                      <button class="absolute right-0 top-1/2 -translate-y-1/2 w-9 h-full border-none flex items-center justify-center">
                        <iconify-icon icon="heroicons-solid:search"></iconify-icon>
                      </button>
                    </div>
                  </div>

                  <div class="input-area">
                    <div class="relative">
                      <input type="password" class="form-control" placeholder="Password">
                    </div>
                  </div>

                  <div class="input-area">
                    <div class="relative">
                      <input type="text" class="form-control !pl-9" placeholder="Username">
                      <span class="absolute left-0 top-1/2 -translate-y-1/2 w-9 h-full border-none flex items-center justify-center">
                        @
                      </span>
                    </div>
                  </div>

                  <div class="input-area">
                    <div class="relative">
                      <input type="text" class="form-control !pr-32" placeholder="Username">
                      <span class="absolute right-0 top-1/2 px-3 -translate-y-1/2 h-full border-none flex items-center justify-center">
                        @example.com
                      </span>
                    </div>
                  </div>

                  <div class="input-area">
                    <div class="relative">
                      <input type="text" class="form-control !pl-52" placeholder="Username">
                      <span class="absolute left-0 top-1/2 px-3 -translate-y-1/2 h-full border-none flex items-center justify-center">
                        https://example.com/users/
                      </span>
                    </div>
                  </div>

                  <div class="input-area">
                    <div class="relative">
                      <input type="text" class="form-control !px-9" placeholder="100">
                      <span class="absolute left-0 top-1/2 -translate-y-1/2 w-9 h-full border-none flex items-center justify-center">
                        $
                      </span>
                      <span class="absolute right-0 top-1/2 -translate-y-1/2 w-9 h-full border-none flex items-center justify-center">
                        .00
                      </span>
                    </div>
                  </div>

                </div>
              </div>
            </div>
        </div>
    </div>
</x-app-layout>
