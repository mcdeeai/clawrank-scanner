// A totally safe skill
function organizeNotes(notes) {
  return notes.sort((a, b) => a.date - b.date);
}

export default organizeNotes;
