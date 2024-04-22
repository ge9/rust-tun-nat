use slotmap::{DefaultKey, Key, SlotMap};


struct Node<T> {
    value: T,
    prev: DefaultKey,
    next: DefaultKey,
}

pub struct LList<T> {
    sm: SlotMap<DefaultKey, Node<T>>,
    head: DefaultKey,
    tail: DefaultKey,
}
pub struct LLIter<'a, T>(pub &'a LList<T>,pub DefaultKey);
impl <'a,T>Iterator for LLIter<'a,T> {
    type Item = (&'a T,DefaultKey);
    fn next(&mut self) -> Option<Self::Item> {
        let curr = self.1;
        self.1 = self.0.next(self.1)?;
        Some((self.0.get(curr)?,curr))
    }
}


impl<T> LList<T> {
    pub fn new() -> Self {
        Self {
            sm: SlotMap::with_key(),
            head: DefaultKey::null(),
            tail: DefaultKey::null(),
        }
    }
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.sm.len()
    }

    pub fn push_head(&mut self, value: T) -> DefaultKey {
        let k = self.sm.insert(Node {
            value,
            prev: DefaultKey::null(),
            next: self.head,
        });

        if let Some(old_head) = self.sm.get_mut(self.head) {
            old_head.prev = k;
        } else {
            self.tail = k;
        }
        self.head = k;
        k
    }

    pub fn push_tail(&mut self, value: T) -> DefaultKey {
        let k = self.sm.insert(Node {
            value,
            prev: self.tail,
            next: DefaultKey::null(),
        });

        if let Some(old_tail) = self.sm.get_mut(self.tail) {
            old_tail.next = k;
        } else {
            self.head = k;
        }
        self.tail = k;
        k
    }
    //assume key is null xor valid
    pub fn push_before(&mut self, key: DefaultKey, value: T) -> DefaultKey {
        if key.is_null(){return self.push_tail(value)};
        let prev = self.sm.get(key).unwrap().prev;
        if prev.is_null() {return self.push_head(value)};
        let k = self.sm.insert(Node {
            value,
            prev: prev,
            next: key,
        });
        self.sm.get_mut(prev).unwrap().next = k;
        self.sm.get_mut(key).unwrap().prev = k;
        k
    }

    pub fn pop_head(&mut self) -> Option<T> {
        //self.remove(self.head);
        self.sm.remove(self.head).map(|old_head| {
            self.head = old_head.next;
            if let Some(next_node) = self.sm.get_mut(old_head.next) {
                next_node.prev = old_head.prev;
            } else {
                self.tail = old_head.prev;//=null
            }
            old_head.value
        })
    }
    #[allow(dead_code)]
    pub fn pop_tail(&mut self) -> Option<T> {
        //self.remove(self.tail);
        self.sm.remove(self.tail).map(|old_tail| {
            if let Some(prev_node) = self.sm.get_mut(old_tail.prev) {
                prev_node.next = old_tail.next;
            } else {
                self.head = old_tail.next;//=null
            }
            self.tail = old_tail.prev;
            old_tail.value
        })
    }
    #[allow(dead_code)]
    pub fn remove(&mut self, key: DefaultKey) -> Option<T> {
        self.sm.remove(key).map(|node| {
            if let Some(prev_node) = self.sm.get_mut(node.prev) {
                prev_node.next = node.next;
            } else {
                self.head = node.next;
            }

            if let Some(next_node) = self.sm.get_mut(node.next) {
                next_node.prev = node.prev;
            } else {
                self.tail = node.prev;
            }

            node.value
        })
    }

    pub fn move_to_tail_and_get(&mut self, key: DefaultKey) -> &mut T {
        let (prev, next) = {let n = self.sm.get(key).unwrap();(n.prev, n.next)};
        if let Some(next_node) = self.sm.get_mut(next)
        {next_node.prev = prev}
        else{return self.get_mut(key).unwrap()};//this is already the tail
        if let Some(prev_node) = self.sm.get_mut(prev) {
            prev_node.next = next;
        } else {
            self.head = next;
        }
        let old_tail = self.sm.get_mut(self.tail).unwrap();
        old_tail.next = key;
        self.sm.get_mut(key).unwrap().prev = self.tail;
        self.sm.get_mut(key).unwrap().next = DefaultKey::null();
        self.tail = key;
        self.get_mut(key).unwrap()
    }
    pub fn move_before_and_get(&mut self, before_this_key: DefaultKey, key: DefaultKey) -> &mut T {
        if before_this_key.is_null(){return self.move_to_tail_and_get(key)};
        if before_this_key == key {return self.get_mut(key).unwrap()}

        let (prev, next) = {let n = self.sm.get(key).unwrap();(n.prev, n.next)};
        //remove
        if let Some(prev_node) = self.sm.get_mut(prev) {
            prev_node.next = next;
        } else {
            self.head = next;
        }
        if let Some(next_node) = self.sm.get_mut(next) {
            next_node.prev = prev;
        } else {
            self.tail = prev;
        }
        //insert
        //before_this_key is head
        if self.sm.get(before_this_key).unwrap().prev.is_null() {
            self.head = key;
            self.sm.get_mut(key).unwrap().prev = DefaultKey::null();
        }else{
            let prev = self.sm.get(before_this_key).unwrap().prev;
            self.sm.get_mut(prev).unwrap().next = key;
            self.sm.get_mut(key).unwrap().prev = prev;
        }
        self.sm.get_mut(key).unwrap().next = before_this_key;
        self.sm.get_mut(before_this_key).unwrap().prev = key;

        self.get_mut(key).unwrap()
    }
    pub fn head(&self) -> DefaultKey {
        self.head
    }
    #[allow(dead_code)]
    pub fn tail(&self) -> DefaultKey {
        self.tail
    }
    pub fn next(&self, key: DefaultKey) -> Option<DefaultKey>{
        Some(self.sm.get(key)?.next)
    }

    pub fn get(&self, key: DefaultKey) -> Option<&T> {
        self.sm.get(key).map(|node| &node.value)
    }
    pub fn get2(&self, key: DefaultKey) -> Option<(&T, DefaultKey)> {
        self.sm.get(key).map(|node| (&node.value, node.next))
    }

    pub fn get_mut(&mut self, key: DefaultKey) -> Option<&mut T> {
        self.sm.get_mut(key).map(|node| &mut node.value)
    }
}
