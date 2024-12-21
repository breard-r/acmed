#!/usr/bin/env bash
#
# This script creates a new release and is therefore not meant to be
# used by anyone but the project manager. It will therefore remain
# undocumented and may assume some specific environment.

abort_release()
{
    echo "Aborting."
    exit 1
}

display_crate_version()
{
    local crate_version

    crate_version=$(grep "^version" "Cargo.toml" | cut -d '"' -f2)
    echo "Current version: ${crate_version}"
}

update_crate_version()
{
    local new_version="$2"

    sed -i "s/^version = .*/version = \"${new_version}\"/" "/Cargo.toml"
}

display_man_date()
{
    local man_name="$1"
    local man_date

    man_date=$(grep ".Dd" "man/en/${man_name}" | sed "s/\.Dd //")
    echo "Current date for ${man_name}: ${man_date}"
}

update_man_date()
{
    local man_name="$1"
    local new_date="$2"

    sed -i "s/\.Dd .*/\.Dd ${new_date}/" "man/en/${man_name}"
}

update_changelog()
{
    local new_version="$1"
    local new_date=$(date "+%Y-%m-%d")

    sed -i "s/\[Unreleased\]/\[${new_version}\] - ${new_date}/" "CHANGELOG.md"
}

check_working_directory()
{
    local status

    status=$(git status --untracked-files="no" --porcelain="2")
    if [[ "$status" != "" ]]; then
        echo "Unable to create a new release while the working directory is not clean."
        abort_release
    fi
}

commit_new_version()
{
    local new_version="$1"

    git add --update
    git commit -m "ACMEd v${new_version}"
    git tag -m "ACMEd v${new_version}" "v${new_version}"

    echo
    echo "Version ${new_version} has been committed and tagged."
    echo "If everything is correct, you can publish if using:"
    echo "  git push"
    echo "  git push origin v${new_version}"
}

release_new_version()
{
    local new_version="$1"
    local current_date="$2"
    local confirm_git_diff

    update_crate_version "${new_version}"

    update_man_date "acmed.8" "${current_date}"
    update_man_date "acmed.toml.5" "${current_date}"

    update_changelog "${new_version}"

    cargo update

    git diff

    echo
    echo -n "Does everything seems ok? [y|N] "
    read -r confirm_git_diff

    case "${confirm_git_diff}" in
        y|Y) commit_new_version "${new_version}";;
        *)
            git restore "."
            abort_release
            ;;
    esac
}

main()
{
    local new_version
    local confirm_release

    check_working_directory

    display_crate_version

    echo
    display_man_date "acmed.8"
    display_man_date "acmed.toml.5"

    echo
    echo -n "Enter the new version: "
    read -r new_version

    export LC_TIME="en_US.UTF-8"
    current_date=$(date "+%b %d, %Y")

    echo
    echo "You are about to release version ${new_version} on ${current_date}"
    echo -n "Are you sure? [y/N] "
    read -r confirm_release

    case "${confirm_release}" in
        y|Y) release_new_version "${new_version}" "${current_date}";;
        *) abort_release;;
    esac
}

main
