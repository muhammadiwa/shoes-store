<x-app-layout>
    <div class="space-y-8">
        <div>
          <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="grid xl:grid-cols-2 grid-cols-1 gap-6">
            <!-- Basic Inputs -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Basic Inputs</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-y-4">
                        <div class="input-area">
                            <label for="name" class="form-label">Project Name*</label>
                            <input id="name" type="text" class="form-control" placeholder="Project Name">
                        </div>
                        <div class="input-area">
                            <label for="readonly" class="form-label">Readonly Input</label>
                            <input id="readonly" type="text" class="form-control" placeholder="You can't change me.(Readonly)" readonly="readonly"></div>
                        <div class="input-area">
                            <label for="disable" class="form-label">Disabled</label>
                            <input id="disable" type="text" class="form-control" placeholder="Disabled" disabled="disabled"></div>
                        <div class="input-area">
                            <label for="description" class="form-label">Project Description</label>
                            <textarea id="description" rows="5" class="form-control" placeholder="Type Here"></textarea>
                        </div>
                        <div class="input-area">
                            <label for="select" class="form-label">Select Option</label>
                            <select id="select" class="form-control">
                                <option value="option1" class="dark:bg-slate-700">Options 1</option>
                                <option value="option2" class="dark:bg-slate-700">Options 2</option>
                                <option value="option3" class="dark:bg-slate-700">Options 3</option>
                                <option value="option4" class="dark:bg-slate-700">Options 4</option>
                            </select>
                        </div>
                    </div>
                </div>
            </div>
            <!-- Sized Inputs -->
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
                                <label for="largeInput" class="form-label">Large Input</label>
                                <input id="largeInput" type="text" class="form-control !text-lg" placeholder="Large Input"></div>
                            <div class="input-area">
                                <label for="defaultInput" class="form-label">Default Input</label>
                                <input id="defaultInput" type="text" class="form-control" placeholder="Default Input">
                            </div>
                            <div class="input-area">
                                <label for="smallInput" class="form-label">Small Input</label>
                                <input id="smallInput" type="text" class="form-control !py-1 !text-xs" placeholder="Project Name"></div>
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
                            <div class="input-area relative pl-28">
                                <label for="largeInput" class="mb-2 absolute left-0 top-1/2 -translate-y-1/2 block cursor-pointer font-Inter font-medium capitalize
                                                                text-slate-700 dark:text-slate-50 leading-6">
                                    Large Input</label>
                                <input id="largeInput" type="text" class="form-control !text-lg" placeholder="Large Input"></div>
                            <div class="input-area relative pl-28">
                                <label for="defaultInput" class="mb-2 absolute left-0 top-1/2 -translate-y-1/2 block cursor-pointer font-Inter font-medium capitalize
                                                                    text-slate-700 dark:text-slate-50 leading-6">
                                    Default Input</label>
                                <input id="defaultInput" type="text" class="form-control" placeholder="Default Input"></div>
                            <div class="input-area relative pl-28">
                                <label for="smallInput" class="mb-2 absolute left-0 top-1/2 -translate-y-1/2 block cursor-pointer font-Inter font-medium capitalize
                                                                        text-slate-700 dark:text-slate-50 leading-6">
                                    Small Input</label>
                                <input id="smallInput" type="text" class="form-control !py-1 !text-xs" placeholder="Project Name"></div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- States Inputs -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">States</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-y-4">
                        <div class="input-area">
                            <label for="name" class="form-label">Valid State</label>
                            <div class="relative">
                                <input id="name" type="text" class="form-control !border-success-500 !pr-9" placeholder="Valid">
                                <iconify-icon class="absolute top-1/2 right-3 -translate-y-1/2 text-success-500 text-xl" icon="heroicons-outline:check"></iconify-icon>
                            </div>
                            <span class="font-Inter text-sm text-success-500 pt-2 inline-block">This is valid state.</span>
                        </div>
                        <div class="input-area">
                            <label for="name" class="form-label">Invalid State</label>
                            <div class="relative">
                                <input id="name" type="text" class="form-control !border-danger-500 !pr-9" placeholder="Invalid">
                                <iconify-icon class="absolute top-1/2 right-3 -translate-y-1/2 text-danger-500 text-xl" icon="mdi:warning-octagon-outline"></iconify-icon>
                            </div>
                            <span class="font-Inter text-sm text-danger-500 pt-2 inline-block">This is invalid state.</span>
                        </div>
                    </div>
                </div>
            </div>
            <!-- Validation Inputs -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Input Validation States With Tootltips</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-y-4">
                        <div class="input-area">
                            <label for="name" class="form-label">Valid State</label>
                            <div class="relative">
                                <input id="name" type="text" class="form-control !border-success-500 !pr-9" placeholder="Valid">
                                <iconify-icon class="absolute top-1/2 right-3 -translate-y-1/2 text-success-500 text-xl" icon="heroicons-outline:check"></iconify-icon>
                            </div>
                            <span class="font-Inter text-xs text-white bg-success-500 rounded px-2 py-1 mt-2 inline-block">This is valid state.</span>
                        </div>
                        <div class="input-area">
                            <label for="name" class="form-label">Invalid State</label>
                            <div class="relative">
                                <input id="name" type="text" class="form-control !border-danger-500 !pr-9" placeholder="Invalid">
                                <iconify-icon class="absolute top-1/2 right-3 -translate-y-1/2 text-danger-500 text-xl" icon="mdi:warning-octagon-outline"></iconify-icon>
                            </div>
                            <span class="font-Inter text-xs text-white bg-danger-500 rounded px-2 py-1 mt-2 inline-block">This is invalid state.</span>
                        </div>
                    </div>
                </div>
            </div>
            <!-- Formatter Support -->
            <div class="card xl:col-span-2 rounded-md bg-white dark:bg-slate-800 lg:h-full shadow-base">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Formatter Support</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-y-4">
                        <div class="input-area">
                            <label for="textFormatter" class="form-label">Text Input With Formatter (On Input)</label>
                            <div class="relative">
                                <input id="textFormatter" type="text" class="form-control lowercase" placeholder="Text Formatter">
                                <span class="text-xs font-Inter font-normal text-slate-400 mt-2 inline-block">We will convert your text to lowercase instantly</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</x-app-layout>
