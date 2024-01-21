<x-app-layout>
    <div class="space-y-8">
        <div>
          <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="space-y-6">
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Radio Button</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-y-4">
                        <div class="flex items-center space-x-7 flex-wrap">
                            <div class="basicRadio">
                                <label class="flex items-center cursor-pointer">
                                    <input type="radio" class="hidden" name="basicradios" value="secondary-500" checked="checked">
                                    <span class="flex-none bg-white dark:bg-slate-500 rounded-full border inline-flex ltr:mr-2 rtl:ml-2 relative transition-all
                                            duration-150 h-[16px] w-[16px] border-slate-400 dark:border-slate-600 dark:ring-slate-700"></span>
                                    <span class="text-secondary-500 text-sm leading-6 capitalize">Checked</span>
                                </label>
                            </div>
                            <div class="basicRadio">
                                <label class="flex items-center cursor-pointer">
                                    <input type="radio" class="hidden" name="basicradios" value="secondary-500">
                                    <span class="flex-none bg-white dark:bg-slate-500 rounded-full border inline-flex ltr:mr-2 rtl:ml-2 relative transition-all
                                                duration-150 h-[16px] w-[16px] border-slate-400 dark:border-slate-600 dark:ring-slate-700"></span>
                                    <span class="text-secondary-500 text-sm leading-6 capitalize">Unchecked</span>
                                </label>
                            </div>
                            <div class="basicRadio">
                                <label class="flex items-center cursor-not-allowed">
                                    <input type="radio" class="hidden" name="diasbaledradio" value="secondary-500" checked="checked" disabled="disabled">
                                    <span class="flex-none bg-white dark:bg-slate-500 rounded-full border inline-flex ltr:mr-2 rtl:ml-2 relative transition-all
                                                    duration-150 h-[16px] w-[16px] border-slate-400 dark:border-slate-600 dark:ring-slate-700"></span>
                                    <span class="text-secondary-500 text-sm leading-6 capitalize">Checked</span>
                                </label>
                            </div>
                            <div class="basicRadio">
                                <label class="flex items-center cursor-not-allowed">
                                    <input type="radio" class="hidden" name="diasbaledradio" value="secondary-500" disabled="disabled">
                                    <span class="flex-none bg-white dark:bg-slate-500 rounded-full border inline-flex ltr:mr-2 rtl:ml-2 relative transition-all
                                                        duration-150 h-[16px] w-[16px] border-slate-400 dark:border-slate-600 dark:ring-slate-700"></span>
                                    <span class="text-secondary-500 text-sm leading-6 capitalize">Unchecked</span>
                                </label>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Color Radio Button</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-y-4">
                        <div class="flex items-center space-x-7 flex-wrap">
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
                                <div class="{{ $item }}-radio">
                                    <label class="flex items-center cursor-pointer">
                                        <input type="radio" class="hidden" name="coloredRadio" value="{{ $item }}-500" checked="checked">
                                        <span class="flex-none bg-white dark:bg-slate-500 rounded-full border inline-flex ltr:mr-2 rtl:ml-2 relative transition-all
                                                                duration-150 h-[16px] w-[16px] border-slate-400 dark:border-slate-600 dark:ring-slate-700"></span>
                                        <span class="text-{{ $item }}-500 text-sm leading-6 capitalize">{{ $item }}</span>
                                    </label>
                                </div>
                            @endforeach
                        </div>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Array Radio Button</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-y-4">
                        <div class="space-y-2">
                            <div class="secondary-radio">
                                <label class="flex items-center cursor-pointer  ">
                                    <input type="radio" class="hidden" name="arrayRadio[]" value="Apple">
                                    <span class="flex-none bg-white dark:bg-slate-500 rounded-full border inline-flex ltr:mr-2 rtl:ml-2 relative transition-all
                                                                duration-150 h-[16px] w-[16px] border-slate-400 dark:border-slate-600 dark:ring-slate-700"></span>
                                    <span class="text-slate-900 font-Inter font-normal text-sm leading-6 capitalize dark:text-slate-300">Apple</span>
                                </label>
                            </div>
                            <div class="secondary-radio">
                                <label class="flex items-center cursor-pointer  ">
                                    <input type="radio" class="hidden" name="arrayRadio[]" value="Banana">
                                    <span class="flex-none bg-white dark:bg-slate-500 rounded-full border inline-flex ltr:mr-2 rtl:ml-2 relative transition-all
                                                                    duration-150 h-[16px] w-[16px] border-slate-400 dark:border-slate-600 dark:ring-slate-700"></span>
                                    <span class="text-slate-900 font-Inter font-normal text-sm leading-6 capitalize dark:text-slate-300">Banana</span>
                                </label>
                            </div>
                            <div class="secondary-radio">
                                <label class="flex items-center cursor-pointer  ">
                                    <input type="radio" class="hidden" name="arrayRadio[]" value="Orange">
                                    <span class="flex-none bg-white dark:bg-slate-500 rounded-full border inline-flex ltr:mr-2 rtl:ml-2 relative transition-all
                                                                        duration-150 h-[16px] w-[16px] border-slate-400 dark:border-slate-600 dark:ring-slate-700"></span>
                                    <span class="text-slate-900 font-Inter font-normal text-sm leading-6 capitalize dark:text-slate-300">Orange</span>
                                </label>
                            </div>
                        </div>
                        <p>Selected Items: [<span id="radioSelectedItems"></span>]
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</x-app-layout>
