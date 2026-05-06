(function() {
    'use strict';

    function patchList({
        container,
        items,
        getKey,
        getSignature,
        renderItem,
        emptyHtml = '',
    }) {
        if (!container) return false;
        if (!items.length) {
            if (emptyHtml) {
                container.innerHTML = emptyHtml;
            } else {
                container.replaceChildren();
            }
            return true;
        }

        const existingMap = new Map(
            Array.from(container.children)
                .filter((node) => node.nodeType === Node.ELEMENT_NODE)
                .map((node) => [node.dataset.patchKey, node])
        );

        const fragment = document.createDocumentFragment();
        let changed = false;

        items.forEach((item, index) => {
            const key = String(getKey(item, index));
            const signature = String(getSignature(item, index));
            const existing = existingMap.get(key);
            if (existing && existing.dataset.patchSignature === signature) {
                fragment.appendChild(existing);
                return;
            }
            const nextNode = renderItem(item, index);
            nextNode.dataset.patchKey = key;
            nextNode.dataset.patchSignature = signature;
            fragment.appendChild(nextNode);
            changed = true;
        });

        if (!changed && container.childElementCount === items.length) {
            return false;
        }

        container.replaceChildren(fragment);
        return true;
    }

    window.DomPatchList = {
        patchList,
    };
})();
