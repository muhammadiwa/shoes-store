<x-app-layout>
    <div class="space-y-8">
        <div>
          <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="space-y-6">
            <!-- BEGIN: Basic checkbox -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Checkboxes</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-y-4">
                        <div class="flex items-center space-x-7 flex-wrap">
                            <div class="checkbox-area">
                                <label class="inline-flex items-center cursor-pointer">
                                    <input type="checkbox" class="hidden" name="checkbox">
                                    <span class="h-4 w-4 border flex-none border-slate-100 dark:border-slate-800 rounded inline-flex ltr:mr-3 rtl:ml-3 relative transition-all duration-150 bg-slate-100 dark:bg-slate-900">
                                        <img src="images/icon/ck-white.svg" alt="" class="h-[10px] w-[10px] block m-auto opacity-0"></span>
                                    <span class="text-slate-500 dark:text-slate-400 text-sm leading-6">Unchecked</span>
                                </label>
                            </div>
                            <div class="checkbox-area">
                                <label class="inline-flex items-center cursor-pointer">
                                    <input type="checkbox" class="hidden" name="checkbox" checked="checked">
                                    <span class="h-4 w-4 border flex-none border-slate-100 dark:border-slate-800 rounded inline-flex ltr:mr-3 rtl:ml-3 relative transition-all duration-150 bg-slate-100 dark:bg-slate-900">
                                        <img src="images/icon/ck-white.svg" alt="" class="h-[10px] w-[10px] block m-auto opacity-0"></span>
                                    <span class="text-slate-500 dark:text-slate-400 text-sm leading-6">Checked</span>
                                </label>
                            </div>
                            <div class="checkbox-area">
                                <label class="inline-flex items-center cursor-not-allowed opacity-50">
                                    <input type="checkbox" class="hidden" name="checkbox" disabled="disabled">
                                    <span class="h-4 w-4 border flex-none border-slate-100 dark:border-slate-800 rounded inline-flex ltr:mr-3 rtl:ml-3 relative transition-all duration-150 bg-slate-100 dark:bg-slate-900">
                                        <img src="images/icon/ck-white.svg" alt="" class="h-[10px] w-[10px] block m-auto opacity-0"></span>
                                    <span class="text-slate-500 dark:text-slate-400 text-sm leading-6">Checked Disabled</span>
                                </label>
                            </div>
                            <div class="checkbox-area">
                                <label class="inline-flex items-center cursor-not-allowed opacity-50">
                                    <input type="checkbox" class="hidden" name="checkbox" checked="checked" disabled="disabled">
                                    <span class="h-4 w-4 border flex-none border-slate-100 dark:border-slate-800 rounded inline-flex ltr:mr-3 rtl:ml-3 relative transition-all duration-150 bg-slate-100 dark:bg-slate-900">
                                        <img src="images/icon/ck-white.svg" alt="" class="h-[10px] w-[10px] block m-auto opacity-0"></span>
                                    <span class="text-slate-500 dark:text-slate-400 text-sm leading-6">Unchecked Disabled</span>
                                </label>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Basic Checkbox -->

            <!-- BEGIN: Color Checkbox -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Color Checkboxes</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-y-4">
                        <div class="flex flex-wrap">
                            <?php
                                $basicColor = [
                                    "primary",
                                    "secondary",
                                    "info",
                                    "success",
                                    "warning",
                                    "danger"
                                ]
                            ?>
                            @foreach ($basicColor as $item)
                                <div class="checkbox-area {{ $item }}-checkbox mr-2 sm:mr-4 mt-2">
                                    <label class="inline-flex items-center cursor-pointer">
                                        <input type="checkbox" class="hidden" name="checkbox" value="{{ $item }}" checked="checked">
                                        <span class="h-4 w-4 border flex-none border-slate-100 dark:border-slate-800 rounded inline-flex ltr:mr-3 rtl:ml-3 relative transition-all duration-150 bg-slate-100 dark:bg-slate-900">
                                            <img src="images/icon/ck-white.svg" alt="" class="h-[10px] w-[10px] block m-auto opacity-0"></span>
                                        <span class="text-{{ $item }}-500 dark:text-slate-400 text-sm leading-6 capitalize">{{ $item }}</span>
                                    </label>
                                </div>
                            @endforeach
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Color Checkbox -->

            <!-- BEGIN: Using Options Array -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Using Options Array</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-y-4">
                        <div class="space-y-3">
                            <div class="checkbox-area">
                                <label class="inline-flex items-center cursor-pointer">
                                    <input type="checkbox" class="hidden" value="Apple" name="arrayCheckbox[]">
                                    <span class="h-4 w-4 border flex-none border-slate-100 dark:border-slate-800 rounded inline-flex ltr:mr-3 rtl:ml-3 relative transition-all duration-150 bg-slate-100 dark:bg-slate-900">
                                        <img src="images/icon/ck-white.svg" alt="" class="h-[10px] w-[10px] block m-auto opacity-0"></span>
                                    <span class="text-slate-500 dark:text-slate-400 text-sm leading-6">Apple</span>
                                </label>
                            </div>
                            <div class="checkbox-area">
                                <label class="inline-flex items-center cursor-pointer">
                                    <input type="checkbox" class="hidden" value="Banana" name="arrayCheckbox[]">
                                    <span class="h-4 w-4 border flex-none border-slate-100 dark:border-slate-800 rounded inline-flex ltr:mr-3 rtl:ml-3 relative transition-all duration-150 bg-slate-100 dark:bg-slate-900">
                                        <img src="images/icon/ck-white.svg" alt="" class="h-[10px] w-[10px] block m-auto opacity-0"></span>
                                    <span class="text-slate-500 dark:text-slate-400 text-sm leading-6">Banana</span>
                                </label>
                            </div>
                            <div class="checkbox-area">
                                <label class="inline-flex items-center cursor-pointer">
                                    <input type="checkbox" class="hidden" value="Orange" name="arrayCheckbox[]">
                                    <span class="h-4 w-4 border flex-none border-slate-100 dark:border-slate-800 rounded inline-flex ltr:mr-3 rtl:ml-3 relative transition-all duration-150 bg-slate-100 dark:bg-slate-900">
                                        <img src="images/icon/ck-white.svg" alt="" class="h-[10px] w-[10px] block m-auto opacity-0"></span>
                                    <span class="text-slate-500 dark:text-slate-400 text-sm leading-6">Orange</span>
                                </label>
                            </div>
                        </div>
                        <p>Selected Items: [<span id="selectedItems"></span>]
                        </p>
                    </div>
                </div>
            </div>
            <!-- END: Using Options Array -->
        </div>
    </div>
</x-app-layout>
