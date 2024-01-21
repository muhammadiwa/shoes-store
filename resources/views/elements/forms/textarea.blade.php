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
                            <div class="card-title text-slate-900 dark:text-white">Basic Textarea</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-y-4">
                        <div class="input-area">
                            <label for="textarea" class="form-label">Text Area</label>
                            <textarea id="textarea" class="form-control" placeholder="Text Area"></textarea>
                        </div>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Displayed Rows</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-y-4">
                        <div class="input-area">
                            <label for="DrowsTextarea" class="form-label">Text Area</label>
                            <textarea id="DrowsTextarea" class="form-control" rows="5" placeholder="Text Area"></textarea>
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
                        <div class="input-area flex items-center">
                            <label for="largeTextarea" class="form-label !w-[100px]">Large</label>
                            <textarea id="largeTextarea" class="form-control" rows="5" placeholder="Large Input"></textarea>
                        </div>
                        <div class="input-area flex items-center">
                            <label for="defaultTextarea" class="form-label !w-[100px]">Default</label>
                            <textarea id="defaultTextarea" class="form-control" rows="3" placeholder="Default Input"></textarea>
                        </div>
                        <div class="input-area flex items-center">
                            <label for="smallTextarea" class="form-label !w-[100px]">Small</label>
                            <textarea id="smallTextarea" class="form-control" rows="1" placeholder="Small Input"></textarea>
                        </div>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">States</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-y-4">
                        <div class="input-area">
                            <label for="validTextarea" class="form-label">Valid State</label>
                            <div class="relative">
                                <textarea
                                    id="validTextarea"
                                    class="form-control !border-success-500 focus:!shadow-none focus:ring-0 focus:!outline-none"
                                    rows="3"
                                    placeholder="Valid Area"></textarea>
                                <iconify-icon class="absolute top-1/2 right-3 -translate-y-1/2 text-success-500 text-xl" icon="heroicons-outline:check"></iconify-icon>
                            </div>
                            <span class="font-Inter text-sm text-success-500 pt-2 inline-block">This is valid state.</span>
                        </div>
                        <div class="input-area">
                            <label for="invalidTextarea" class="form-label">Invalid State</label>
                            <div class="relative">
                                <textarea
                                    id="validTextarea"
                                    class="form-control !border-danger-500 focus:!shadow-none focus:ring-0 focus:!outline-none"
                                    rows="3"
                                    placeholder="Valid Area"></textarea>
                                <iconify-icon
                                    class="absolute top-1/2 right-3 -translate-y-1/2 text-danger-500 text-xl"
                                    icon="mdi:warning-octagon-outline"></iconify-icon>
                            </div>
                            <span class="font-Inter text-sm text-danger-500 pt-2 inline-block">This is valid state.</span>
                        </div>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Input Validation States With Tootltips</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-y-4">
                        <div class="input-area">
                            <label for="validTextarea" class="form-label">Valid State</label>
                            <div class="relative">
                                <textarea
                                    id="validTextarea"
                                    class="form-control !border-success-500 focus:!shadow-none focus:ring-0 focus:!outline-none"
                                    rows="3"
                                    placeholder="Valid Area"></textarea>
                                <iconify-icon class="absolute top-1/2 right-3 -translate-y-1/2 text-success-500 text-xl" icon="heroicons-outline:check"></iconify-icon>
                            </div>
                            <span class="font-Inter text-xs text-white bg-success-500 rounded px-2 py-1 mt-2 inline-block">This is valid state.</span>
                        </div>
                        <div class="input-area">
                            <label for="invalidTextarea" class="form-label">Invalid State</label>
                            <div class="relative">
                                <textarea
                                    id="validTextarea"
                                    class="form-control !border-danger-500 focus:!shadow-none focus:ring-0 focus:!outline-none"
                                    rows="3"
                                    placeholder="Valid Area"></textarea>
                                <iconify-icon
                                    class="absolute top-1/2 right-3 -translate-y-1/2 text-danger-500 text-xl"
                                    icon="mdi:warning-octagon-outline"></iconify-icon>
                            </div>
                            <span class="font-Inter text-xs text-white bg-danger-500 rounded px-2 py-1 mt-2 inline-block">This is invalid state.</span>
                        </div>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Formatter Support</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-y-4">
                        <div class="input-area">
                            <label for="validTextarea" class="form-label">Text Input With Formatter (On Input)</label>
                            <div class="relative">
                                <textarea id="validTextarea" class="form-control lowercase" rows="3" placeholder="Enter Your Name"></textarea>
                                <span class="text-xs font-Inter font-normal text-slate-400 mt-2 inline-block">We will convert your text to lowercase
                                    instantly</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</x-app-layout>
